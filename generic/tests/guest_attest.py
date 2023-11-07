import logging
import os

from avocado.utils import process
from virttest import utils_conn
from virttest import utils_misc
from virttest import utils_net
from virttest import error_context

LOG_JOB = logging.getLogger('avocado.test')


@error_context.context_aware
def run(test, params, env):
    """
    Guest attestation validation test:
    1) Fetches required certs from KDS 
    2) Verifies the downloaded certs
    3) Imports the certs into hypervisor
       memory.
    4) Generates attestation report inside
       guest.
    5) Verifies the attestation report.

    :param test: kvm test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    #timeout = float(params.get("login_timeout", 240))
    snphost_gitrepo = params.get("host_tool_git")
    snphost_version = params.get("host_tool_version")
    #snpguest_gitrepo = params.get("guest_tool_git")
    #snpguest_version = params.get("guest_tool_version")
    host_attest_build_path = utils_misc.get_path(test.debugdir, "snphost")
    #guest_attest_build_path = utils_misc.get_path(test.debugdir, "snpguest")
    snphost_download_cmd = "git clone --depth 1 %s -b %s %s" % (snphost_gitrepo, snphost_version, host_attest_build_path)
    #snpguest_download_cmd = "git clone --depth 1 %s -b %s %s" % (snpguest_gitrepo, snpguest_version, guest_attest_build_path)
    #vms = params.get("vms").split(" ")
    #vm_list = []
    #session_list = []
    # Get the rust build environment ready
    test.log.info("Get the rust build environment ready")
    if process.run("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh", shell=True).exit_status == 0:
        process.run("export PATH=$PATH:~/.cargo/bin")
    else:
        test.error("Failed to build rust")
    if process.run("rustc --version", ignore_status=True).exit_status == 0:
        test.log.info("rust installed successfully...")
    else:
        test.error("Failed to load rust")
    test.log.info("Cloning %s", snphost_gitrepo)
    process.run(snphost_download_cmd, shell=True)
    if process.run("cd %s;git log -1;cargo build" % (host_attest_build_path), shell=True).exit_status != 0:
        test.error("Failed to build snphost tool from %s/%s" % (snphost_gitrepo,snphost_version))
    else:
        test.log.info("snphost built successfully...")
    """
    try:
        for vm_name in vms:
            vm = env.get_vm(vm_name)
            vm.verify_alive()
            vm_list.append(vm)

            load_snpguest(test, vm, timeout)

            session = kdump_enable(vm, vm_name, crash_kernel_prob_cmd,
                                   kernel_param_cmd, kdump_enable_cmd, timeout)

            session_list.append(session)

        for vm in vm_list:
            error_context.context("Kdump Testing, force the Linux kernel"
                                  " to crash", test.log.info)
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
                                  " a crash", test.log.info)
            check_vmcore(test, vm_list[i], session_list[i], crash_timeout)
    finally:
        for s in session_list:
            s.close()
        for vm in vm_list:
            postprocess_kdump(test, vm, timeout)
            vm.destroy()
    """
