"""
Local live migration from source to destination VM with CTX7 Mellanox passthrough device.
"""

import os
import re

import six
from avocado.utils import genio, linux_modules, pci, process
from avocado.utils.software_manager.manager import SoftwareManager
from virttest import env_process, utils_misc

# pylint: disable=broad-exception-raised, broad-exception-caught


def run(
    test, params, env
):  # pylint: disable=R0914, disable=too-many-branches, too-many-statements
    """
    Run local live migration from source to destination VM with CTX7 Mellanox VFs passthrough
    device. This supports
    1. IOMMU Dirty Tracking and
    2. Device Dirty Tracking (legacy) testing.

    Steps:
      1) Perform all prechecks for the user-provided Mellanox network card.
         a) Validate user input device is CTX7 Mellanox network card.
         b) iproute package with version >= 6.2 is installed. Required tool for migration.
         c) Validate CTX7 Mellanox firmware (≥ 28.43.1000 or ≥ 32.42.1100).
         d) Check mlxconfig required supports:
            SRIOV_EN=1, NUM_OF_VFS≥2, VF_MIGRATION_MODE=2, LINK_TYPE_P1=2.
      2) Create 2 Mellanox VFs
      3) Enable migration capability for both VFs created.
      4) Attach/Bind mlx5_vfio_pci driver to both VFs.
      5) Create 2 VMs and passthrough one VF to each.
      6) Start local live migration and wait till migration completes.
      7) Validate if local live migration completed successfully.

    :param test: QEMU test object.
    :param params: Dictionary with test parameters:
        - pci_device: Pci device to passthrough. Default: ""
        - mode: Defines guest modes - [apic, x2apic]. Default: x2apic.
        - kvm_probe_module_parameters: To enable/disable avic on host.
                                       Possible values ["avic=1", "avic=0"]
        - login_timeout: VM login timeout in seconds. Default: 240.
        - mig_timeout : Migration timeout duration. Default: 1600s
        - mig_protocol: Migration protocol to use. Default: tcp.
        - src_params: Addtional source VM QEMU cmdline params.
        - dest_params: Addtional destination VM QEMU cmdline params.
        - iommu_dirty_tracking: Enable IOMMU Dirty Tracking. default: yes
    :param env: Dictionary with test environment.
    :raises: cancel if
                1. Prechecks for required mellanox support not present.
                2. Not able to create 2 VFs.
                3. Not able to enable required mellanox support.
                4. Not able to bind VFs to mlx5_vfio_pci
                5. Not able to enable IOMMU Dirty Tracking.
                6. Unable to passthrough VFs to VMs resp.
             fails if
                1. Unable to start migration.
                2. Unable to complete migration process.
                3. Migration is unsuccessful.
    """

    try:
        iommu_dirty_tracking = params.get("iommu_dirty_tracking", "yes")
        mig_timeout = params.get_numeric("mig_timeout", 1600, float)
        mig_protocol = params.get("migration_protocol", "tcp")
        pci_device = params.get("pci_device", None)
        dest_params = params.get("dest_params", "")
        src_params = params.get("src_params", "")
        vf_created = False
        mlnx_mode = None
        dest_vm = None
        vm = None

        if pci_device:
            # ---------------------------------------
            # Validate PCI input + existence on host
            # ---------------------------------------
            if pci_device not in pci.get_pci_addresses():
                test.cancel(
                    "Please provide full pci address of a valid pci device on system.\n"
                    f"Received: {pci_device}\n"
                    f"Available devices on system: {pci.get_pci_addresses()}"
                )

            # -------------------------------------
            # Validate Mellanox Vendor ID (0x15b3)
            # -------------------------------------
            vendor_id = pci.get_vendor_id(pci_device)
            vendor_id = vendor_id.split(":")[0]

            if vendor_id != "15b3":
                test.cancel(
                    f"PCI device '{pci_device}' is not Mellanox Network Card.\n"
                    f"Vendor reported: {vendor_id} (expected: 15b3)"
                )

            test.log.debug(
                f"{pci_device}: Mellanox vendor verified (vendor={vendor_id})"
            )

            # ------------------------------------------------------
            # Validate CTX7 Vendor device Id (Can be extended)
            # ------------------------------------------------------
            ctx7_device_ids = {"1020", "1021"}

            device_id = pci.get_pci_prop(pci_device, "Device")

            if device_id not in ctx7_device_ids:
                test.cancel(
                    f"PCI device '{pci_device}' is not a CTX7 Mellanox Network Card.\n"
                    f"CTX7 vendor device Id reported: {device_id}\n"
                    f"Expected: {sorted(ctx7_device_ids)}"
                )
            test.log.debug(
                f"{pci_device}: CTX7 vendor device Id verified (device_id={device_id})"
            )

            # ---------------------------------------------
            # Required iproute2 >= 6.2  + migratable enable
            # ---------------------------------------------
            out = process.system_output("ip -V", shell=True).decode()

            m = re.search(r"iproute2-([\d.]+)", out)
            if not m:
                test.cancel(f"Unable to detect iproute2 package version:\n{out}")

            if tuple(map(int, m.group(1).split("."))) < (6, 2):
                test.cancel(
                    f"iproute2 version {m.group(1)} < 6.2, (Required for migration)."
                )

            test.log.debug(
                f"iproute2 version {m.group(1)} 'migratable' supported. (Required for migration)."
            )

            # ------------------------------------------------------------------
            # Firmware Version Check ( FW version >= 28.41.1000 or 32.41.1000))
            # ------------------------------------------------------------------
            out = process.system_output(
                f"devlink dev info pci/{pci_device}", ignore_status=False, shell=True
            ).decode()

            match = re.search(r"fw\.version.*\s+([\d.]+)", out)
            if not match:
                test.cancel(
                    "Unable to detect mellanox firmware version from devlink output."
                )

            fw = match.group(1)

            def fw_is_supported(fw):
                try:
                    major, minor, build = map(int, fw.split("."))
                except ValueError:
                    return False

                return (
                    major == 28 and (minor > 41 or (minor == 41 and build >= 1000))
                ) or (major == 32 and (minor > 41 or (minor == 41 and build >= 1100)))

            if not fw_is_supported(fw):
                test.cancel(
                    f"Unsupported mellanox firmware version.\n"
                    f"Detected: {fw}\n"
                    f"Required:\n"
                    f"  - >= 28.43.1000 (28.x branch)\n"
                    f"  - >= 32.42.1100 (32.x branch)"
                )

            test.log.debug(f"{pci_device}: Mellanox firmware OK ({fw}) for migration.")

            # --------------------------------------------------------------------------------------
            # Pre-req mlnx config checks for vf migration and other required capability enablements
            # --------------------------------------------------------------------------------------
            cmd = f"mlxconfig -d {pci_device} q"
            output = process.run(cmd, ignore_status=False, shell=True).stdout_text

            expected = {
                "SRIOV_EN": "True(1)",
                "NUM_OF_VFS": "2",
                "VF_MIGRATION_MODE": "MIGRATION_ENABLED(2)",
                "LINK_TYPE_P1": "ETH(2)",
            }
            for key, value in expected.items():
                if key not in output:
                    test.cancel(
                        f"mlxconfig: Mellanox config '{key}' not found for the device."
                    )

                for line in output.splitlines():
                    if line.strip().startswith(key):
                        if line.strip().startswith("NUM_OF_VFS"):
                            if line.split()[-1] in {"0", "1"}:
                                test.cancel(
                                    "mlxconfig: Unexpected value for NUM_OF_VFS.\n"
                                    f"Expected: >= 2. Found: {line.split()[-1]}"
                                )
                        elif line.split()[-1] != value:
                            test.cancel(
                                f"mlxconfig: Unexpected value for {key}.\n"
                                f"Expected: {value}\n"
                                f"Found: {line.split()[-1]}"
                            )

            test.log.debug(
                f"{pci_device}: Supports expected mlnx config required for live migration\n"
                f"{expected}"
            )

            # -----------------------------------------------------------
            # Mellanox legacy mode to switchdev for migration capability
            # -----------------------------------------------------------
            cmd = f"devlink dev eswitch show pci/{pci_device}"
            output = process.run(
                cmd, ignore_status=False, shell=True
            ).stdout_text.strip()
            mlnx_mode = output.split()[2]

            process.run(
                f"devlink dev eswitch set pci/{pci_device} mode switchdev",
                ignore_status=False,
                shell=True,
            )

            out = process.system_output(
                f"devlink dev eswitch show pci/{pci_device}",
                ignore_status=False,
                shell=True,
            ).decode()

            if "mode switchdev" not in out:
                test.cancel(
                    "Failed to set mellanox eSwitch mode from legacy to switchdev.\n"
                )

            test.log.debug(
                f"{pci_device}: Successfully set mellanox eSwitch mode as switchdev"
            )

            # -------------------------------
            # Check, create and validate VFs
            # -------------------------------
            sriov_totalvfs_path = f"/sys/bus/pci/devices/{pci_device}/sriov_totalvfs"
            sriov_numvfs_path = f"/sys/bus/pci/devices/{pci_device}/sriov_numvfs"
            try:
                total_vfs = int(genio.read_one_line(sriov_totalvfs_path).strip())
            except Exception as e:
                test.cancel(
                    f"Failed to read total number of VFs supported by mellanox: {e}"
                )

            if total_vfs < 2:
                test.cancel(
                    f"Mellanox {pci_device} supports only {total_vfs} VFs. "
                    "At least 2 are required."
                )

            # Disable existing VFs first
            try:
                genio.write_file_or_fail(sriov_numvfs_path, "0")
            except Exception:
                pass

            # Create 2 VFs
            try:
                genio.write_file_or_fail(sriov_numvfs_path, "2")
            except Exception as e:
                test.cancel(f"Failed to create 2 VFs on mellanox {pci_device}: {e}")

            try:
                vf_dir = f"/sys/bus/pci/devices/{pci_device}"
                virtfns = [
                    os.path.basename(os.path.realpath(os.path.join(vf_dir, f)))
                    for f in os.listdir(vf_dir)
                    if f.startswith("virtfn")
                ]
            except Exception as e:
                test.cancel(f"Unable to read VF PCI devices: {e}")

            if len(virtfns) != 2:
                test.cancel(
                    f"Expected 2 VFs but found {len(virtfns)}.\n" f"Detected: {virtfns}"
                )

            vf_created = True
            test.log.debug(f"{pci_device}: Successfully created 2 VFs")

            # -------------------------------
            # Unbind mlx5_core from both VFs
            # -------------------------------
            try:
                vf_pci_devices = sorted(virtfns)
                for vf_pci_device in vf_pci_devices:
                    cur_driver = pci.get_driver(vf_pci_device)
                    if cur_driver is not None:
                        pci.unbind(cur_driver, vf_pci_device)
            except Exception as e:
                test.cancel(f"Unable to unbind driver of VFs {vf_pci_devices}")

            test.log.debug(f"Successfully unbound drivers of VF {vf_pci_devices}")

            # -------------------------------------------------
            # Enable migratable capability for the mellanox VFs
            # -------------------------------------------------
            for vf_index in (1, 2):
                port = f"pci/{pci_device}/{vf_index}"

                out = process.system_output(
                    f"devlink port show {port}", shell=True
                ).decode()

                if not re.search(r"migratable\s+(enable|disable)", out):
                    test.cancel(
                        f"'migratable' capability not found for the mellanox VF:\n{out}"
                    )

                if re.search(r"migratable\s+(disable)", out):
                    test.log.debug("Enabling migratable")
                    process.run(
                        f"devlink port function set {port} migratable enable",
                        shell=True,
                    )

                out = process.system_output(
                    f"devlink port show {port}", shell=True
                ).decode()
                if "migratable enable" not in out:
                    test.cancel(
                        f"Failed to enable migratable capability for mellanox VF:\n{out}"
                    )

            test.log.debug(
                "Migratable capability verified as enabled for both mellanox VFs created"
            )

            # -------------------------------
            # Bind mlx5_vfio_pci to both VFs
            # -------------------------------
            smm = SoftwareManager()
            if not smm.check_installed("mstflint") and not smm.install("mstflint"):
                test.cancel("mstflint package not found and installing failed")

            try:
                linux_modules.configure_module("mlx5_vfio_pci", "CONFIG_MLX5_VFIO_PCI")
            except Exception as e:
                test.cancel(f"{e}")

            try:
                for vf_pci_device in vf_pci_devices:
                    pci.attach_driver(vf_pci_device, "mlx5_vfio_pci")
            except Exception as e:
                test.cancel(
                    f"Unable to bind driver mlx5_vfio_pci to VFs {vf_pci_devices}: {e}"
                )

            test.log.debug(
                f"Successfullly binded VFs {vf_pci_devices} to mlx5_vfio_pci driver"
            )

            # ---------------------------------------------------------------------
            # Presetup for IOMMU dirty tracking support for vfio passthrough device
            # ---------------------------------------------------------------------
            if iommu_dirty_tracking == "yes":
                if (
                    linux_modules.check_kernel_config("CONFIG_IOMMUFD_DRIVER")
                    != linux_modules.ModuleConfig.BUILTIN
                ):
                    test.cancel("Kernel doesnot support IOMMU Dirty tracking")

                try:
                    linux_modules.configure_module("iommufd", "CONFIG_IOMMUFD")
                except Exception as e:
                    test.cancel(f"{e}")

                if (
                    linux_modules.check_kernel_config("CONFIG_VFIO_DEVICE_CDEV")
                    != linux_modules.ModuleConfig.BUILTIN
                ):
                    test.cancel(
                        "Required CONFIG_VFIO_DEVICE_CDEV config for IOMMU Dirty tracking not set"
                    )

        # ---------------------------------
        # Local Live Migration between VFs
        # ---------------------------------
        test.log.debug("Starting test: Local Live Migration between VFs")

        # Create a clone of source VM as destination VM
        try:
            vm = env.get_vm(params["main_vm"])
            dest_vm = vm.clone()
        except Exception as e:
            test.cancel(f"Failed to clone source VM for destination VM: {str(e)}")

        # Passthrough VF1 to source VM and launch it.
        try:
            if pci_device:
                if iommu_dirty_tracking == "yes":
                    params["extra_params"] += " -object iommufd,id=iommu0"
                    params["extra_params"] += (
                        f" -device vfio-pci,host={vf_pci_devices[0]}"
                        ",iommufd=iommu0,x-device-dirty-page-tracking=off"
                    )
                else:
                    params[
                        "extra_params"
                    ] += f" -device vfio-pci,host={vf_pci_devices[0]}"
            params["extra_params"] += f" {src_params}"
            params["start_vm"] = "yes"
            env_process.preprocess_vm(test, params, env, params.get("main_vm"))
            vm.verify_alive()
        except Exception as e:
            test.cancel(f"Failed to launch Source VM: {str(e)}")

        # Login into source VM.
        try:
            session = vm.wait_for_login()
            test.log.debug(f"Debug: {session.cmd_output('dmesg')}")
        except Exception as e:
            test.cancel(f"Failed to login Source VM: {str(e)}")

        # Passthrough VF2 to destination VM
        try:
            if pci_device:
                if iommu_dirty_tracking == "yes":
                    dest_vm.params["extra_params"] += " -object iommufd,id=iommu0"
                    dest_vm.params["extra_params"] += (
                        f" -device vfio-pci,host={vf_pci_devices[1]}"
                        ",iommufd=iommu0,x-device-dirty-page-tracking=off"
                    )
                else:
                    dest_vm.params[
                        "extra_params"
                    ] += f" -device vfio-pci,host={vf_pci_devices[1]}"
            dest_vm.params["extra_params"] += f" {dest_params}"
            dest_vm.create(migration_mode=mig_protocol, mac_source=vm)
        except Exception as e:
            test.cancel(f"Failed to create destination VM: {str(e)}")

        # Enable migration on source and destination VM
        try:
            uri = f"tcp:0:{dest_vm.migration_port}"
            dest_vm.monitor.migrate_incoming(uri)
            dest_vm.monitor.set_migrate_capability(True, "return-path")
            dest_vm.monitor.set_migrate_capability(True, "switchover-ack")
            vm.monitor.set_migrate_capability(True, "return-path")
            vm.monitor.set_migrate_capability(True, "switchover-ack")
        except Exception as e:
            test.fail(
                f"Enabling migration capability on source and destination VMs. Reason: {e}"
            )

        # Start local live migration from source to destination VM.
        try:
            vm.monitor.migrate(uri)
        except Exception as e:
            test.fail(f"Starting local live migration between VMs failed. Reason: {e}")

        def migration_finished():
            if dest_vm.is_dead():
                raise Exception("Destination VM died during migration.")
            if vm.is_dead():
                raise Exception("Source VM died during migration")
            try:
                info = vm.monitor.info("migrate")
                if isinstance(info, six.string_types):
                    return "status: completed" in info
                return info.get("status") == "completed"
            except Exception:
                return False

        def wait_for_migration():
            if not utils_misc.wait_for(
                migration_finished,
                mig_timeout,
                2,
                2,
                "Waiting for migration process to finish",
            ):
                raise Exception("Timeout expired while waiting for migration to finish")

        # Check if migration process is successfully completed.
        try:
            wait_for_migration()
        except Exception as e:
            test.fail(
                f"Process of local live migration between VMs failed midway. Reason: {e}"
            )

        # Validate migration is successfully completed.
        try:
            info = vm.monitor.info("migrate")
            if isinstance(info, six.string_types):
                if "status: completed" not in info:
                    test.fail(f"Local Live Migration between VFs failed.Reason: {info}")
            else:
                if info.get("status") != "completed":
                    test.fail(
                        f"Local Live Migration between VFs failed. Reason: {info}"
                    )
        except Exception as e:
            test.fail(f"Local Live Migration between VMs failed: Reason: {e}")

        test.log.debug("Local Live Migration between VMs completed successfully.")

    # ---------
    # TearDown
    # ---------
    finally:
        if vm:
            vm.destroy()
        if dest_vm:
            dest_vm.destroy()

        # Disable/Destroy created VFs
        try:
            if vf_created:
                genio.write_file_or_fail(sriov_numvfs_path, "0")
        except Exception as e:
            test.cancel(f"Failed to destroy VFs created for {pci_device}: {e}")

        # Mellanox eSwitch mode back to initial state
        if pci_device and mlnx_mode:
            try:
                process.run(
                    f"devlink dev eswitch set pci/{pci_device} mode {mlnx_mode}",
                    ignore_status=False,
                    shell=True,
                )

                out = process.system_output(
                    f"devlink dev eswitch show pci/{pci_device}",
                    ignore_status=False,
                    shell=True,
                ).decode()

                if f"mode {mlnx_mode}" not in out:
                    test.cancel(
                        f"Failed to set mellanox eSwitch mode back to {mlnx_mode}.\n"
                    )

                test.log.debug(
                    f"{pci_device}: Successfully set mellanox eSwitch mode as {mlnx_mode}"
                )
            except Exception as e:
                test.cancel(
                    f"Failed to set mellanox eSwitch mode back to {mlnx_mode}: {e}"
                )
