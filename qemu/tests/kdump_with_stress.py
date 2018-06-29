import logging
import os
import time
from avocado.utils import download

from virttest import error_context
from virttest import utils_test
from virttest import utils_misc
from virttest import utils_net
from avocado.core import exceptions
from virttest.utils_iptables import Iptables


@error_context.context_aware
def run(test, params, env):
    """
    KVM kdump test with stress:
    1) Log into a guest
    2) Check, configure and enable the kdump
    3) Load stress with netperf/stress tool in guest
    4) Trigger a crash by 'sysrq-trigger' and check the vmcore for each vcpu,
       or only trigger one crash with nmi interrupt and check vmcore.

    :param test: kvm test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    timeout = float(params.get("login_timeout", 240))
    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()
    kdump_guest = utils_test.Kdump(test, params)
    netperf_server_cmd = params.get("netperf_server_cmd", "netserver -p {0}")
    netperf_client_cmd = params.get("netperf_client_cmd", "netperf -H {0} -p {1} -l {2} -t {3}")
    ports = params.get("ports", "16604")
    stress_duration = params.get("stress_duration", "20")
    test_protocol = params.get("test_protocols", "TCP_STREAM")
    ip_rule = params.get("ip_rule", "")
    netperf_para_sess = params.get("netperf_para_sessions", "1")
    session = vm.wait_for_login(timeout=timeout)
    kdump_guest.preprocess_kdump(test, vm, timeout)
    kdump_guest.kdump_enable(test, vm, timeout)

    try:
        params['server_pwd'] = params.get("password")
        params['stress_cmds_netperf'] = netperf_server_cmd.format(ports)
#        if ip_rule:
#            for ip_addr in [vm.get_address(), utils_net.get_host_ip_address(params)]:
#                params['server_ip'] = ip_addr
#                Iptables.setup_or_cleanup_iptables_rules([ip_rule], params=params, cleanup=False)
#                params['server_pwd'] = params.get("hostpassword")
#        stress_host = utils_test.Stress("netperf", params)
#        stress_host.load_stress_tool()
        params['server_ip'] = vm.get_address()
        params['server_pwd'] = params.get("password")
        params['stress_cmds_netperf'] = netperf_client_cmd.format(utils_net.get_host_ip_address(params), ports, stress_duration, test_protocol)
#        stress_client = utils_test.VMStress(vm, "netperf", params)
#        for num in xrange(int(netperf_para_sess)):
#            stress_client.load_stress_tool()
        error_context.context("Kdump Testing, force the Linux kernel to crash",
                              logging.info)
        kdump_guest.crash_test(test, vm, timeout)
#        vm.wait_for_login()
#        stress_host.clean()
#        stress_client.clean()
    except exceptions.TestError  as error:
        logging.error(error)
    finally:
        session.close()
        vm.destroy()
