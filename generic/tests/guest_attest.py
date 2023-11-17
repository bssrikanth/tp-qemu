import logging
import os
import sys

from avocado.utils import process
from virttest import utils_conn
from virttest import utils_misc
from virttest import utils_net
from virttest import error_context

LOG_JOB = logging.getLogger('avocado.test')

@error_context.context_aware
def load_snpguest(test, vm, vmname, timeout):
    """
    load snpguest in guest.

    :param vm_name: vm name
    :param timeout: Timeout in seconds
    """
    snpguest_gitrepo = vm.params.get("guest_tool_git")
    snpguest_version = vm.params.get("guest_tool_version")
    guest_attest_build_path = vm.params.get("guest_dst_dir")
    session = vm.wait_for_login(timeout=timeout)
    # Get the rust build environment ready
    test.log.info("Get the rust build environment ready inside the guest %s" % vmname)
    rust_setup_cmd = "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    status, output = session.cmd_status_output(rust_setup_cmd)
    rust_path = "~/.cargo/bin"
    test.log.info("rust setup log: %s" % output)
    if status != 0:
        test.error("Failed to build rust inside guest %s: %s" % (vmname,output))
    status, output = session.cmd_status_output("%s/rustc --version" % rust_path)
    if status == 0:
        test.log.info("rust installed successfully...")
    else:
        test.error("Failed to load rust on guest %s" % vmname)
    test.log.info("Cloning %s", snpguest_gitrepo)
    snpguest_download_cmd = "git clone --depth 1 %s -b %s %s/snpguest" % (snpguest_gitrepo, snpguest_version, guest_attest_build_path)
    test.log.info("Loading snpguest on %s" % vmname)
    status, output = session.cmd_status_output(snpguest_download_cmd)
    if status != 0:
        test.log.error(output)
        test.error("Fail to clone snpguest on %s check logs" % vmname)
    else:
        test.log.info("Cloning snpguest on %s was success" % vmname)
    snpguest_build = "cd %s/snpguest;%s/cargo build" % (guest_attest_build_path, rust_path)
    status, output = session.cmd_status_output(snpguest_build,timeout=300)
    if status != 0:
        test.error("Failed to build snpguest tool from %s/%s: %s" % (snpguest_gitrepo, snpguest_version, output))
    else:
        test.log.info("snpguest built successfully...")
    session.close()

@error_context.context_aware
def unload_snpguest(test, vm, timeout):
    """
    Check, configure and enable the kdump in guest.

    :param vm_name: vm name
    :param timeout: Timeout in seconds
    """
    snpguest_gitrepo = vm.params.get("guest_tool_git")
    snpguest_version = vm.params.get("guest_tool_version")
    guest_attest_build_path = vm.params.get("guest_dst_dir")
    rust_path = "~/.cargo/bin"
    session = vm.wait_for_login(timeout=timeout)
    test.log.info("Unloading snpguest on %s" % vm.name)
    status, output = session.cmd_status_output("rm -rf %s/snpguest" % guest_attest_build_path)
    if status != 0:
        test.log.error(output)
        test.error("Fail to unload snpguest on %s check logs" % vm.name)
    else:
        test.log.info("Unloading snpguest on %s was success" % vm.name)
    #uninstall rust on guest
    snpguest_rustuninstall = "%s/rustup self uninstall -y" % rust_path
    status, output = session.cmd_status_output(snpguest_rustuninstall)
    if status != 0:
        test.error("Failed to uninstall rust inside %s: %s" % (vm.name,output))
    else:
        test.log.info("rust uninstalled successfully... on %s" % vm.name)
    session.close()

@error_context.context_aware
def verify_attestation(test, vm, vmname, timeout):
    """
    Check, configure and enable the kdump in guest.

    :param vm_name: vm name
    :param timeout: Timeout in seconds
    """
    guest_attest_build_path = vm.params.get("guest_dst_dir")
    session = vm.wait_for_login(timeout=timeout)
    test.log.info("Generate report on %s" % vmname)
    status, output = session.cmd_status_output("cd %s/snpguest/target/debug;mkdir reportdir;mkdir fetchdir;./snpguest report --random ./reportdir/report.bin ./reportdir/randomfile" % guest_attest_build_path)
    if status != 0:
        test.log.error(output)
        test.error("Fail to generate report on %s check logs" % vmname)
    else:
        test.log.info("Report generation on %s was success" % vmname)

    test.log.info("Import certificates on %s" % vmname)
    status, output = session.cmd_status_output("cd %s/snpguest/target/debug;./snpguest certificates pem ./fetchdir" % guest_attest_build_path)
    if status != 0:
        test.log.error(output)
        test.error("Fail to fetch host certificates on %s check logs" % vmname)
    else:
        test.log.info("Fetch host certificates on %s was success" % vmname)

    test.log.info("Verify imported certificates on %s" % vmname)
    status, output = session.cmd_status_output("cd %s/snpguest/target/debug;./snpguest verify certs ./fetchdir" % guest_attest_build_path)
    if status != 0:
        test.log.error(output)
        test.error("Imported certificates verification failed on %s check logs" % vmname)
    else:
        test.log.info("Imported certificates verification on %s was success" % vmname)

    test.log.info("Verify attestation on %s" % vmname)
    status, output = session.cmd_status_output("cd %s/snpguest/target/debug;./snpguest verify attestation ./fetchdir ./reportdir/report.bin" % guest_attest_build_path)
    if status != 0:
        test.log.error(output)
        test.error("SNP Guest attestation verification failed on %s check logs" % vmname)
    else:
        test.log.info("SNP Guest attestation verification on %s was success" % vmname)
    session.close()

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

    timeout = float(params.get("login_timeout", 240))
    snphost_gitrepo = params.get("host_tool_git")
    snphost_version = params.get("host_tool_version")
    host_attest_build_path = utils_misc.get_path(test.debugdir, "snphost")
    snphost_download_cmd = "git clone --depth 1 %s -b %s %s" % (snphost_gitrepo, snphost_version, host_attest_build_path)
    vms = params.get("vms").split(" ")
    vm_list = []
    # Get the rust build environment ready on host
    test.log.info("Get the rust build environment ready")
    if process.run("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y", shell=True).exit_status == 0:
        cur_home = os.environ["HOME"]
        rust_path = "%s/.cargo/bin" % cur_home
    else:
        test.error("Failed to build rust")
    if process.run("%s/rustc --version" % (rust_path), ignore_status=True).exit_status == 0:
        test.log.info("rust installed successfully...")
    else:
        test.error("Failed to load rust")
    test.log.info("Cloning %s", snphost_gitrepo)
    process.run(snphost_download_cmd, shell=True)
    if process.run("cd %s;git log -1;%s/cargo build" % (host_attest_build_path,rust_path), shell=True).exit_status != 0:
        test.error("Failed to build snphost tool from %s/%s" % (snphost_gitrepo,snphost_version))
    else:
        test.log.info("snphost built successfully...")
    # host snp environment verification
    if process.run("%s/target/debug/snphost ok" % (host_attest_build_path), shell=True).exit_status != 0:
        test.error("Host enviornment test failed for snp! check logs")

    if process.run("cd %s/target/debug;mkdir fetchdir;mkdir exportdir;./snphost reset;./snphost fetch ca pem ./fetchdir/;./snphost fetch vcek pem ./fetchdir/;./snphost verify ./fetchdir/ark.pem ./fetchdir/ask.pem ./fetchdir/vcek.pem" % (host_attest_build_path), shell=True).exit_status != 0:
        test.error("Host certificate fetch failed from KDS!! check logs")

    if process.run("cd %s/target/debug;./snphost import ./fetchdir/;./snphost export pem ./exportdir/;./snphost verify ./exportdir/ark.pem ./exportdir/ask.pem ./exportdir/vcek.pem" % (host_attest_build_path), shell=True).exit_status != 0:
        test.error("Host certificate import and verification failed!! check logs")
    else:
        test.log.info("Host certificates fetched, imported and verified successfully...")
    #run snpguest loading, attestation validation and clean on all vms
    try:
        for vm_name in vms:
            vm = env.get_vm(vm_name)
            vm.verify_alive()
            vm_list.append(vm)
            load_snpguest(test, vm, vm_name, timeout)
            verify_attestation(test, vm, vm_name, timeout)
    finally:
        for vm in vm_list:
            unload_snpguest(test, vm, timeout)
            vm.destroy()
    #uninstall rust on host
    if process.run("%s/rustup self uninstall -y" % rust_path, shell=True).exit_status != 0:
        test.error("Failed to uninstall rust")
    else:
        test.log.info("rust uninstalled successfully...")
