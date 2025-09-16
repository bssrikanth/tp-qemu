import os
import re

from avocado.utils import process
from virttest import error_context, virt_vm


@error_context.context_aware
def run(test, params, env):
    """
    QEMU test case to verify the snp related kernel parameters,
    ensuring the VM boot behavior and host compatibility matches expectations.
    :param test: QEMU test object for logging and test control.
    :param params: Dictionary with test parameters. Below are the main parameters.
        - param_to_check: Kernel command line parameter to verify (default: "sev=no_snp").
        - vm_boot_expected: Boolean indicating if the VM is expected to boot (default: False).
        - host_snp_supported: Boolean indicating if host support is expected (default: False).
        - error_pattern: when found indicates absence for kernel support for the param_to_check.
    :param env: Dictionary with test environment, including VM configuration.
    """
    error_context.context("Setting up test environment", test.log.info)
    param_to_check = params.get("param_to_check", "sev=nosnp")
    vm_boot_expected = params.get_boolean("vm_boot_expected", False)
    host_snp_supported = params.get_boolean("host_snp_supported", False)
    cvm_module_path = params.get("cvm_module_path")
    kernel_cmdline = params.get("kernel_cmdline", "cat /proc/cmdline")
    error_pattern = params.get("error_pattern", "")
    vm = None

    error_context.context("Check host kernel command line", test.log.info)
    try:
        kernel_cmdline = process.run(
            '%s' % kernel_cmdline, shell=True, ignore_status=False)
        output = kernel_cmdline.stdout.decode()
        if not (re.search(r'\b{}\b'.format(re.escape(param_to_check)), output)):
            test.cancel("Could not find %s parameter in commandline %s" %
                        (param_to_check, output))
        test.log.info("Kernel command line option %s found in %s" %
                      (param_to_check, output))
        if len(error_pattern) > 0:
            try:
                process.run("command -v journalctl", shell=True)
                log_output = process.run(
                    "journalctl -k --boot=0", verbose=False, shell=True).stdout_text.strip()
            except process.CmdError as e:
                test.log.warn(
                    "journalctl not available or failed: {}. Falling back to dmesg".format(e))
                log_output = process.run("dmesg").stdout.decode()
            if not log_output.strip():
                test.log.warn(
                    "Could not confirm presence of %s in dmesg/journalctl log" % error_pattern)
            elif error_pattern in log_output:
                test.cancel(
                    "The host kernel does not support %s parameter" % param_to_check)
            else:
                test.log.info(
                    "Error pattern '%s' not found in kernel log" % error_pattern)
    except process.CmdError as e:
        test.cancel(
            "Error determining kernel command line option availability: {}".format(e))
    error_context.context("Check host support", test.log.info)
    try:
        if os.path.exists(cvm_module_path):
            with open(cvm_module_path) as f:
                output = f.read().strip()
                if output in params.objects("module_status"):
                    if not host_snp_supported:
                        test.fail(
                            "Host support for snp present, which is not expected.")
    except Exception as e:
        test.cancel(
            "There were issues in determining host capability: %s" % str(e))
    error_context.context("Test SNP VM boot", test.log.info)
    try:
        vm_name = params["main_vm"]
        vm = env.get_vm(vm_name)
        vm.create()
        vm.verify_alive()
        if not vm_boot_expected:
            test.fail(
                "SNP guest booted despite having %s in the kernel commandline" % param_to_check)
        test.log.info("SNP guest booted as expected with %s", param_to_check)
    except (virt_vm.VMDeadError, virt_vm.VMCreateError) as e:
        if vm_boot_expected:
            test.fail("SNP guest failed to boot: %s" % str(e))
        test.log.info("As expected, SNP guest boot failed: %s" % str(e))
    finally:
        if vm and vm.is_alive():
            vm.destroy()
