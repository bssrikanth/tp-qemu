import logging
import re

from avocado.utils import process
from virttest import utils_misc, utils_package
from virttest.utils_test import StressError, VMStress
from virttest.utils_version import VersionInterval

LOG_JOB = logging.getLogger("avocado.test")


class VMStressBinding(VMStress):
    """
    Run stress tool on VMs, and bind the process to the specified cpu
    """

    def __init__(self, vm, params, stress_args=""):
        super(VMStressBinding, self).__init__(
            vm, "stress", params, stress_args=stress_args
        )
        self.install()

    def load_stress_tool(self, cpu_id):
        """
        Load the stress tool and bind it to the specified CPU

        :param cpu_id: CPU id you want to bind
        """
        cmd = "setsid taskset -c {} {} {} > /dev/null".format(
            cpu_id, self.stress_cmds, self.stress_args
        )
        LOG_JOB.info("Launch stress with command: %s", cmd)
        self.cmd_launch(cmd)
        # wait for stress to start and then check, if not raise StressError
        if not utils_misc.wait_for(
            self.app_running,
            self.stress_wait_for_timeout,
            first=2.0,
            step=1.0,
            text="wait for stress app to start",
        ):
            raise StressError("Stress does not running as expected.")


def get_guest_cpu_ids(session, os_type):
    """
    Get the ids of all CPUs of the guest

    :param session: ShellSession object of VM
    :param os_type: guest os type, windows or linux
    :return: list of cpu id
    """
    if os_type == "windows":
        # Windows can not get each core id of socket, so this function is
        # meaningless, directly returns an empty set
        return set()
    cmd = "grep processor /proc/cpuinfo"
    output = session.cmd_output(cmd)
    return set(map(int, re.findall(r"processor\s+(?::\s)?(\d+)", output, re.M)))


def check_if_vm_vcpu_topology_match(session, os_type, cpuinfo, test, devices=None):
    """
    check the cpu topology of the guest.

    :param session: session Object
    :param os_type: guest os type, windows or linux
    :param cpuinfo: virt_vm.CpuInfo Object
    :param test: QEMU test object
    :param devices: qcontainer.DevContainer Object
    :return: True if guest topology is same as we expected
    """
    if os_type == "linux":
        out = session.cmd_output_safe("lscpu")
        cpu_info = dict(re.findall(r"([A-Z].+):\s+(.+)", out, re.M))
        if str(cpu_info["Architecture"]) == "s390x":
            sockets = int(cpu_info["Socket(s) per book"])
        else:
            sockets = int(cpu_info["Socket(s)"])
        cores = int(cpu_info["Core(s) per socket"])
        threads = int(cpu_info["Thread(s) per core"])
        threads_matched = cpuinfo.threads == threads
    else:
        cmd = (
            'powershell "Get-WmiObject Win32_processor | Format-List '
            'NumberOfCores,ThreadCount"'
        )
        out = session.cmd_output_safe(cmd).strip()
        try:
            cpu_info = [
                dict(re.findall(r"(\w+)\s+:\s(\d+)", cpu_out, re.M))
                for cpu_out in out.split("\n\n")
            ]
            sockets = len(cpu_info)
            cores = int(cpu_info[0]["NumberOfCores"])
            threads = int(cpu_info[0]["ThreadCount"])
        except KeyError:
            LOG_JOB.warning(
                "Attempt to get output via 'powershell' failed, "
                "output returned by guest:\n%s",
                out,
            )
            LOG_JOB.info("Try again via 'wmic'")
            cmd = "wmic CPU get NumberOfCores,ThreadCount /Format:list"
            out = session.cmd_output_safe(cmd).strip()
            try:
                cpu_info = [
                    dict(re.findall(r"(\w+)=(\d+)", cpu_out, re.M))
                    for cpu_out in out.split("\n\n")
                ]
                sockets = len(cpu_info)
                cores = int(cpu_info[0]["NumberOfCores"])
                threads = int(cpu_info[0]["ThreadCount"])
            except KeyError:
                LOG_JOB.error(
                    "Attempt to get output via 'wmic' failed, output"
                    " returned by guest:\n%s",
                    out,
                )
                return False
        if devices:
            # Until QEMU 8.1 there was a different behaviour for thread count in case
            # of Windows guests. It represented number of threads per single core, not
            # the total number of threads available for all cores in socket. Therefore
            # we disable check for older QEMU versions and adjust for newer versions.
            if devices.qemu_version in VersionInterval("[, 8.1.0)"):
                LOG_JOB.warning("ThreadCount is disabled for Windows guests")
                threads_matched = True
            else:
                threads_matched = threads // cores == cpuinfo.threads
        else:
            test.fail("Variable 'devices' must be defined for Windows guest.")

    is_matched = (
        cpuinfo.sockets == sockets and cpuinfo.cores == cores and threads_matched  # pylint: disable=E0606
    )

    if not is_matched:
        LOG_JOB.debug("CPU infomation of guest:\n%s", out)

    return is_matched

def download_and_build_kcpuid(repo_url, repo_branch, func,target_dir, kcpuid_path):
    """
    Downloads the kcpuid directory from the Linux kernel and builds it.

    Args:
        repo_url (str): URL of the Git repository containing kcpuid.
        repo_branch (str): Branch of the repository to clone.
        func (callable): Function to execute shell commands (e.g., subprocess.run wrapper).
        target_dir (str): Directory where the repository will be cloned.
        kcpuid_path (str): Subdirectory in target_dir containing the kcpuid source.
    Returns:
        bool: True if download and build succeed, False otherwise.
    """
    try:
        status, output = func("test -e %s" % target_dir)
        if not status:
            LOG_JOB.info("Removing %s", target_dir)
            status,output = func("rm -rf %s" % target_dir)
            if status:
                LOG_JOB.error("Failed remove %s: %s" % (target_dir, output))
                return False
        LOG_JOB.info(
            "Cloning %s branch: %s to %s",
            repo_url,
            repo_branch,
            target_dir
        )
        status, output = func("git clone --depth 1 --single-branch --branch %s %s %s" % (repo_branch, repo_url, target_dir), 120)
        if status:
            LOG_JOB.error("Failed to download kcpuid: %s", output)
            return False
        LOG_JOB.info("Building kcpuid in %s/%s", target_dir, kcpuid_path)
        status, output = func("cd %s/%s;make"  % (target_dir, kcpuid_path))
        if status:
            LOG_JOB.error("Failed to build kcpuid: %s", output)
            return False
        LOG_JOB.info("Successfully downloaded and built kcpuid")
        return True
    except Exception as e:
        LOG_JOB.error("Failed to download and build kcpuid: %s", e)
        return False

def check_cpu_flags(params, flags, test, session=None):
    """
    Check cpu flags on host or guest.(only for Linux now)
    :param params: Dictionary with the test parameters
    :param flags: checked flags
    :param test: QEMU test object
    :param session: guest session
    """
    func = process.getstatusoutput
    if session:
        func = session.cmd_status_output
    if params.get("use_kcpuid", "no") == "no":
        cmd = "lscpu | grep Flags | awk -F ':'  '{print $2}'"
        status, raw_out = func(cmd)
        if status:
            test.cancel("Failed to detect cpu flags: %s", raw_out)
        out = raw_out.split()
    else:
        if session:
            if not utils_package.package_install(["git", "make", "gcc"], session):
                test.cancel("Unable to install git, make, gcc")
        target_dir = "/var/tmp/linux_kcpuid"
        kcpuid_path = "tools/arch/x86/kcpuid"
        repo_url = params.get("kcpuid_url", "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git")
        repo_branch = params.get("kcpuid_branch","")
        if len(repo_branch.strip()) == 0:
            status, latest_tag = func("curl -s https://www.kernel.org/finger_banner | head -1 | awk -F ':' -v search=\"stable\" '{if ($1 ~ search) {gsub(/^[ ]+/, \"\", $2); print $2}}'")
            if status:
                test.cancel("The user did not specify a repo_branch, and the latest kernel tag could not be fetched.")
            else:
                repo_branch = "v" + latest_tag.strip()
        if not download_and_build_kcpuid(repo_url, repo_branch, func, target_dir, kcpuid_path):
            test.cancel("Failed to build kcpuid, debug log has more information on the error")
        cmd = "%s/%s/kcpuid" % (target_dir, kcpuid_path)
        status, raw_out = func(cmd)
        raw_out = raw_out.replace("\t", "").splitlines()
        if status:
            test.cancel("Failed to detect cpu flags using kcpuid: %s", raw_out)
        out = [item.strip() for item in raw_out]
    missing = [f for f in flags.split() if f not in out]
    if session:
        LOG_JOB.info("Check cpu flags inside guest")
        if missing:
            test.fail("Flag %s not in guest" % missing)
        no_flags = params.get("no_flags")
        if no_flags:
            err_flags = [f for f in no_flags.split() if f in out]
            if err_flags:
                test.fail("Flag %s should not be present in guest" % err_flags)
    else:
        LOG_JOB.info("Check cpu flags on host")
        if missing:
            test.cancel("This host doesn't support flag %s" % missing)


# Copied from unstable module "virttest/cpu.py"
def check_if_vm_vcpu_match(vcpu_desire, vm):
    """
    This checks whether the VM vCPU quantity matches the value desired.

    :param vcpu_desire: vcpu value to be checked
    :param vm: VM Object

    :return: Boolean, True if actual vcpu value matches with vcpu_desire
    """
    vcpu_actual = vm.get_cpu_count("cpu_chk_cmd")
    if isinstance(vcpu_desire, str) and vcpu_desire.isdigit():
        vcpu_desire = int(vcpu_desire)
    if vcpu_desire != vcpu_actual:
        LOG_JOB.debug(
            "CPU quantity mismatched !!! guest said it got %s but we assigned %s",
            vcpu_actual,
            vcpu_desire,
        )
        return False
    LOG_JOB.info("CPU quantity matched: %s", vcpu_actual)
    return True


def check_if_vm_vcpus_match_qemu(vm):
    vcpus_count = vm.params.get_numeric("vcpus_count", 1)
    vcpu_devices = vm.params.objects("vcpu_devices")
    enabled_vcpu_devices = []

    for vcpu_device in vcpu_devices:
        vcpu_params = vm.params.object_params(vcpu_device)
        if vcpu_params.get_boolean("vcpu_enable"):
            enabled_vcpu_devices.append(vcpu_device)
    enabled_count = vm.cpuinfo.smp + (len(enabled_vcpu_devices) * vcpus_count)

    return check_if_vm_vcpu_match(enabled_count, vm)
