import logging
import re

from avocado.utils import process
from avocado.utils.software_manager.manager import SoftwareManager
from virttest import env_process, error_context, utils_misc, virt_vm

MSR_RMP_CFG = 0xC0010136
MSR_RMP_BASE = 0xC0010132
MSR_SYS_CFG = 0xC0010010


@error_context.context_aware
def run(test, params, env):
    """
    QEMU test to validate Segmented RMP.
    This test verifies that the host correctly supports and has enabled AMD SEV-SNP with Segmented Reverse Map Table (RMP).
    """

    def check_segmented_rmp_cpuid():
        result = process.run("cpuid -l 0x8000001F -r -1", shell=True)
        if result.exit_status != 0:
            test.error("cpuid tool failed or leaf 0x8000001f not present")
        eax_line = [
            l for l in result.stdout_text.split(" ") if l.strip().startswith("eax=")
        ][0]
        eax_val = int(eax_line.split("=")[1].strip(), 16)
        # CPUID Fn8000_001F_EAX[SegmentedRmp] (bit 23)
        return bool(eax_val & (1 << 23))

    def rdmsr(msr_hex):
        result = process.run(f"rdmsr -0 {msr_hex}", shell=True)
        return int(result.stdout_text.strip(), 16)

    deps = ["cpuid", "msr-tools"]
    smg = SoftwareManager()
    for package in deps:
        if not smg.check_installed(package):
            if not smg.install(package):
                test.cancel("%s is needed for the test to be run" % package)
    result = process.run("modprobe msr", shell=True)
    if result.exit_status != 0:
        test.error("modprobe msr failed")
    error_context.context("Check if Hardware Platform supports Segmented RMP")
    if not check_segmented_rmp_cpuid():
        test.cancel("Hardware Platform does not support Segmented RMP")
    logging.info("Hardware Platform supports Segmented RMP")
    error_context.context("Check if Segmented RMP is enabled")
    # 0xc0010136 (RMP_CFG): Bit[0]
    rmp_cfg = rdmsr(MSR_RMP_CFG)
    if not (rmp_cfg & 0x1):
        test.cancel(f"Segmented RMP not enabled")
    logging.info("Segmented RMP enabled")

    error_context.context("Verify RMP table initialization")
    # 0xc0010010 (SYS_CFG): Bit [24]
    sys_cfg = rdmsr(MSR_SYS_CFG)
    if not (sys_cfg & (1 << 24)):
        test.cancel("RMP table is not initialized")
    logging.info("RMP table initialized")

    error_context.context("Validate RMP_BASE MSR matches kernel log")
    # 0xc0010132 (RMP_BASE)
    rmp_base_addr = rdmsr(MSR_RMP_BASE) & ((1 << 52) - 1)
    seg_RMP_pattern = "Segmented RMP base table physical range"
    logging.info("RMP_BASE MSR reports 0x%X", rmp_base_addr)
    try:
        process.run("command -v journalctl", shell=True)
        log_output = process.run(
            "journalctl -k --boot=0", verbose=False, shell=True
        ).stdout_text.strip()
    except process.CmdError as e:
        test.log.warn(
            "journalctl not available or failed: {}. Falling back to dmesg".format(e)
        )
        log_output = process.run("dmesg", shell=True).stdout_text.strip()

    if not log_output.strip():
        test.log.warn(
            "Could not confirm presence of segmented RMP in the host kernel logs"
        )
    elif seg_RMP_pattern in log_output:
        test.log.info("The host kernel has initialized segmented RMP support")
    else:
        test.fail(
            "No RMP table range initialization information found in kernel logs"
        )
    rmp_range = re.search(
        r"Segmented RMP base table physical range.*?0x([0-9a-fA-F]+)",
        log_output,
        re.IGNORECASE,
    )
    if not rmp_range:
        test.fail("Could not parse RMP address range from kernel logs")
    kernel_rmp_base = int(rmp_range.group(1), 16)
    logging.info("Kernel reported Segmented RMP base address: 0x%X", kernel_rmp_base)
    if kernel_rmp_base != rmp_base_addr:
        test.fail(
            f"RMP_BASE mismatch: MSR=0x{rmp_base_addr:X} vs kernel=0x{kernel_rmp_base:X}"
        )
    logging.info("Segmented RMP_BASE matches kernel reported Segmented RMP base")

    error_context.context(
        "All host checks passed — launching SNP guest with Segmented RMP"
    )
    vm = None
    try:
        env_process.preprocess_vm(test, params, env, params["main_vm"])
        vm = env.get_vm(params["main_vm"])
        vm.create()
        vm.verify_alive()
        timeout = int(params.get("login_timeout", 360))
        session = vm.wait_for_login(timeout=timeout)
        error_context.context("Verify if guest reports SEV-SNP active")
        utils_misc.verify_sev(session, params, vm)
        session.close()
        logging.info("Segmented RMP validation test pass")
    except (virt_vm.VMDeadError, virt_vm.VMCreateError) as e:
        test.fail("SNP guest failed to boot with segmented RMP: %s" % str(e))
    finally:
        if vm and vm.is_alive():
            vm.destroy()
