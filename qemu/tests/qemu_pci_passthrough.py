"""
Guest boot sanity test with passthrough device in different mode
- Apic, X2apic, Avic, X2avic
"""

import os
from avocado.utils import process, pci, linux_modules, genio
from virttest import env_process


def run(test, params, env):  # pylint: disable=R0915
    """
    Guest boot sanity test with passthrough device
    Steps:
    1. Launch a guest with a vfio pci passthrough device
    2. Verify if vfio pci passthrough of device to guest is successful
       and guest boots in expected mode - apic, avic, x2apic and x2avic.

    :param test: QEMU test object.
    :param params: Dictionary with test parameters:
        - pci_device: Pci device to passthrough. Default: ""
        - mode: Defines guest modes - [apic, x2apic]. Default: x2apic.
        - kvm_probe_module_parameters: To enable/disable avic on host.
                                       Possible values ["avic=1", "avic=0"]
        - login_timeout: VM login timeout in seconds. Default: 240).
    :param env: Dictionary with test environment.
    :raises: cancel if
                1. At start of test, KVM module is not loaded.
                2. KVM, msr, vfio_pci is not built or loadable.
                3. pci_device != ""
                   a. vfio_pci is not built or loadable.
                   b. Interrupt remapping is not enabled on host. Required for
                      passthrough.
                   c. Pci device/s not found on host system.
                4. kvm_probe_module_parameters = "avic=1"
                   a. Host doesnot support expected mode - avic or x2avic.
                   b. Host doesnot have expected mode enabled for guest - avic
                      or x2avic.
             fails if
		1. Pci device cannot be bind to vfio_pci module for passthrough.
                   (pci_device != "")
                2. Unable to login to guest within login timeout.
    """
    kvm_probe_module_parameters = params.get("kvm_probe_module_parameters", "")
    login_timeout = int(params.get("login_timeout", 240))
    pci_device = params.get("pci_device", "")
    mode = params.get("mode", "x2apic")
    driver_list = []
    session = None
    vm = None

    try:

        def configure_module(module, config):
            """
            Check if 'config' is not set, builtin or module.
            Load 'module' if 'config' is set as module.
            Cancel test if 'config' is not set.
            """
            config_status = linux_modules.check_kernel_config(config)
            if config_status == linux_modules.ModuleConfig.NOT_SET:
                test.cancel(f"{config} is not set. Cancelling the test")
            elif config_status == linux_modules.ModuleConfig.MODULE:
                test.log.debug(f"{config} is set as a module.")
                if linux_modules.load_module(module):
                    if linux_modules.module_is_loaded(module):
                        test.log.debug(f"Module {module} loaded successfully")
                    else:
                        test.cancel(f"Module {module} loading failed")
            elif config_status == linux_modules.ModuleConfig.BUILTIN:
                test.log.debug(f"{config} is built-in.")

        def check_avic_support():
            """
            Check if system supports avic.
            """
            cmd = "rdmsr -p 0 0xc00110dd --bitfield 13:13"
            out = process.run(cmd, sudo=True, shell=True).stdout_text.strip()
            if out == "0":
                test.cancel("System doesnot support avic")

        def check_x2avic_support():
            """
            check if system supports x2avic.
            """
            cmd = "rdmsr -p 0 0xc00110dd --bitfield 18:18"
            out = process.run(cmd, sudo=True, shell=True).stdout_text.strip()
            if out == "0":
                test.cancel("System doesnot support x2avic")

        def check_dmesg_avic(mode):
            """
            Check AVIC and x2AVIC status in dmesg logs diff.

            :param mode: Whether apic or x2apic.
            """

            # Check for the "avic enabled" in dmesg (must be present in accelerated mode)
            if not check_kernel_logs("AVIC enabled"):
                test.cancel("AVIC not enabled after loading kvm_amd with avic=1")

            # Check for the "x2avic enabled" only if the test is "x2apic"
            if (not check_kernel_logs("x2AVIC enabled")) and (mode == "x2apic"):
                test.cancel("x2AVIC not enabled after loading kvm_amd with avic=1.")

        def attach_vfio_pci_driver(device):
            """
            Unbind device from attached driver and bind it to vfio-pci driver.

            :param device: pci device
            """

            test.log.debug(f"Attaching vfio-pci driver to device {device}")

            if not os.path.exists("/sys/bus/pci/drivers/vfio-pci"):
                test.cancel("vfio-pci module not found")

            try:
                # Get vendor id of pci device
                output = pci.get_vendor_id(device)
                cmd = f"echo {output} | sed 's/:/ /g'"
                vid = process.run(cmd, sudo=True, shell=True).stdout_text.strip()

                # Add pci_addr vendor id to vfio-pci driver
                cmd = f"echo {vid} | tee /sys/bus/pci/drivers/vfio-pci/new_id"
                out = process.run(cmd, ignore_status=True, shell=True, sudo=True)
                if (out.stderr.decode('utf-8') != "") and ("File exists" not in out.stderr.decode('utf-8')):
                    raise ValueError(f"{out}")

                # unbind the device from its driver
                driver = pci.get_driver(device)
                driver_list.append(f"{driver}")
                if driver is not None:
                    pci.unbind(driver, device)

                # Bind device to vfio-pci driver
                pci.bind("vfio-pci", device)

            except Exception as e:
                test.cancel(f"Not able to attach vfio drive to {device}. Reason: {e}")

        def check_kernel_logs(pattern):
            """
            Check if "pattern" is present in kernel logs.

            :param pattern: string to check in kernel logs
            """
            out = process.run("dmesg", ignore_status=True, verbose=False, sudo=True)
            for line in out.stdout_text.split("\n"):
                if pattern in line:
                    return True
                if line == out.stdout_text.split("\n")[-1]:
                    cmd = "journalctl -k -b"
                    out = process.run(cmd, ignore_status=True, verbose=False, sudo=True)
                    for line in out.stdout_text.split("\n"):
                        if pattern in line:
                            return True
            return False

        def check_passthrough_requirements():
            """
            Validate IOMMU, Interrupt Remapping, and vfio-pci module availability
            """

            # Check if interrupt remapping is enabled on system
            if not check_kernel_logs("AMD-Vi: Interrupt remapping enabled"):
                test.cancel("IOMMU interrupt remaping is not enabled")

            # Check and load vfio-pci module
            configure_module("vfio-pci", "CONFIG_VFIO_PCI")

        def guest_system_details(session):
            """
            Collect guest system details

            :param session: active guest login session
            """
            test.log.debug(f"Debug: {session.cmd_output('cat /etc/os-release')}")
            test.log.debug(f"Debug: {session.cmd_output('uname -a')}")
            test.log.debug(f"Debug: {session.cmd_output('ls /boot/')}")
            test.log.debug(f"Debug: {session.cmd_output('lspci -k')}")
            test.log.debug(f"Debug: {session.cmd_output('lscpu')}")
            test.log.debug(f"Debug: {session.cmd_output('lsblk')}")
            test.log.debug(f"Debug: {session.cmd_output('df -h')}")
            test.log.debug(f"Debug: {session.cmd_output('dmesg')}")

        # Check system support for avic or x2avic
        if kvm_probe_module_parameters == "avic=1":
            configure_module("msr", "CONFIG_X86_MSR")
            if mode == "apic":
                check_avic_support()
            if mode == "x2apic":
                check_x2avic_support()
            # Validate dmesg for avic and x2avic enablement
            check_dmesg_avic(mode)

        # Passthrough device/s and validate if passthrough is successful
        if pci_device != "":
            # Perform pre-checks and prereq enablements before pci passthrough
            check_passthrough_requirements()

            # Prepare for pci passthrough
            for i in range(len(pci_device.split(" "))):
                # Check if device input is valid
                cmd = f"lspci -s {pci_device.split(' ')[i]}"
                out = process.run(cmd, ignore_status=True, shell=True).stdout_text
                if not out:
                    test.cancel(f"{pci_device.split(' ')[i]} not found on the system")

                attach_vfio_pci_driver(pci_device.split(" ")[i])
                params[
                    "extra_params"
                ] += f" -device vfio-pci,host={pci_device.split(' ')[i]}"

        params["start_vm"] = "yes"
        vm = env.get_vm(params["main_vm"])
        try:
            env_process.preprocess_vm(test, params, env, params.get("main_vm"))
            vm.verify_alive()
        except Exception as e:
            test.fail(f"Failed to create VM: {str(e)}")
        try:
            session = vm.wait_for_login(timeout=login_timeout)
        except Exception as e:
            test.fail(f"Failed to login VM: {str(e)}")
        vm.verify_kernel_crash()

        # Collect guest system details
        guest_system_details(session)

    finally:
        if session:
            session.close()
        if vm:
            vm.destroy()
        if pci_device != "" and driver_list:
            for i in range(len(pci_device.split(" "))):
                cmd = f"lspci -s {pci_device.split(' ')[i]}"
                out = process.run(cmd, ignore_status=True, shell=True).stdout_text
                if not out:
                    break
                driver = pci.get_driver(pci_device.split(" ")[i])
                if driver is not None:
                    pci.unbind(driver, pci_device.split(" ")[i])

                # Bind device back to original driver
                if driver_list[i] != 'None':
                    pci.bind(driver_list[i], pci_device.split(" ")[i])
