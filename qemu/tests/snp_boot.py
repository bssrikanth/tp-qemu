import os

from avocado.utils import cpu, process
from virttest import error_context
from virttest.utils_misc import verify_dmesg


@error_context.context_aware
def run(test, params, env):
    """
    Qemu SNP basic test on Milan and above host:
    1. Check host SNP capability
    2. Boot SNP VM
    3. Verify SNP enabled in guest
    4. Check SNP QMP cmd and policy

    :param test: QEMU test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """
    error_context.context("Start sev-snp test", test.log.info)
    timeout = params.get_numeric("login_timeout", 240)

    snp_module_path = params["snp_module_path"]
    if os.path.exists(snp_module_path):
        with open(snp_module_path) as f:
            output = f.read().strip()
        if output not in params.objects("module_status"):
            test.cancel("Host sev-snp support check fail.")
    else:
        test.cancel("Host sev-snp support check fail.")
    biospath = params.get("bios_path")
    if not os.path.isfile(biospath):
        test.cancel("bios_path not exist %s." % biospath)

    family_id = cpu.get_family()
    model_id = cpu.get_model()
    dict_cpu = {"251": "milan", "2517": "genoa", "2617": "turin"}
    key = str(family_id) + str(model_id)
    host_cpu_model = dict_cpu.get(key, "unknown")

    vm_name = params["main_vm"]
    vm = env.get_vm(vm_name)
    vm.create()
    vm.verify_alive()
    session = vm.wait_for_login(timeout=timeout)
    verify_dmesg()
    vm_policy = vm.params.get_numeric("snp_policy")
    guest_check_cmd = params["snp_guest_check"]
    sev_guest_info = vm.monitor.query_sev()
    if sev_guest_info["snp-policy"] != vm_policy:
        test.fail("QMP snp policy doesn't match %s." % vm_policy)
    try:
        session.cmd_output(guest_check_cmd, timeout=240)
    except Exception as e:
        test.fail("Guest snp verify fail: %s" % str(e))
    finally:
        session.close()
        vm.destroy()
