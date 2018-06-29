import logging
import os

from avocado.utils import process
from virttest import utils_test
from virttest import utils_conn
from virttest import utils_misc
from virttest import utils_net
from virttest import error_context


@error_context.context_aware
def run(test, params, env):
    """
    KVM kdump test:
    1) Log into the guest(s)
    2) Check, configure and enable the kdump
    3) Trigger a crash by 'sysrq-trigger' and check the vmcore for each vcpu,
       or only trigger one crash with 'nmi' interrupt and check vmcore.

    :param test: kvm test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    timeout = float(params.get("login_timeout", 240))
    crash_timeout = float(params.get("crash_timeout", 360))
    def_kernel_param_cmd = ("grubby --update-kernel=`grubby --default-kernel`"
                            " --args=crashkernel=128M")
    kernel_param_cmd = params.get("kernel_param_cmd", def_kernel_param_cmd)
    def_kdump_enable_cmd = "chkconfig kdump on && service kdump restart"
    kdump_enable_cmd = params.get("kdump_enable_cmd", def_kdump_enable_cmd)
    def_crash_kernel_prob_cmd = "grep -q 1 /sys/kernel/kexec_crash_loaded"
    crash_kernel_prob_cmd = params.get("crash_kernel_prob_cmd",
                                       def_crash_kernel_prob_cmd)
    kdump_cfg_path = params.get("kdump_cfg_path", "/etc/kdump.conf")

    vms = params.get("vms", "vm1 vm2").split()
    vm_list = []
    session_list = []

    try:
        for vm_name in vms:
            vm = env.get_vm(vm_name)
            vm.verify_alive()
            vm_list.append(vm)

            preprocess_kdump(test, vm, timeout)
            vm.copy_files_from(kdump_cfg_path,
                               os.path.join(test.debugdir,
                                            "kdump.conf-%s" % vm_name))

            session = kdump_enable(vm, vm_name, crash_kernel_prob_cmd,
                                   kernel_param_cmd, kdump_enable_cmd, timeout)

            session_list.append(session)

        for vm in vm_list:
            error_context.context("Kdump Testing, force the Linux kernel"
                                  " to crash", logging.info)
            crash_cmd = params.get("crash_cmd", "echo c > /proc/sysrq-trigger")

            session = vm.wait_for_login(timeout=timeout)
            vm.copy_files_from(kdump_cfg_path,
                               os.path.join(test.debugdir,
                                            "kdump.conf-%s-test" % vm.name))
            if crash_cmd == "nmi":
                crash_test(test, vm, None, crash_cmd, timeout)
            else:
                # trigger crash for each vcpu
                nvcpu = int(params.get("smp", 1))
                for i in range(nvcpu):
                    crash_test(test, vm, i, crash_cmd, timeout)

        for i in range(len(vm_list)):
            error_context.context("Check the vmcore file after triggering"
                                  " a crash", logging.info)
            check_vmcore(test, vm_list[i], session_list[i], crash_timeout)
    finally:
        for s in session_list:
            s.close()
        for vm in vm_list:
            postprocess_kdump(test, vm, timeout)
            vm.destroy()
