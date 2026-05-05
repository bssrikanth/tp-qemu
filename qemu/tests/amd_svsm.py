import os
import re
import shutil

from avocado.core import exceptions as aex
from avocado.utils import cpu
from avocado.utils import process
from virttest import data_dir as virttest_data_dir
from virttest import error_context
from virttest.utils_misc import verify_dmesg
from virttest.utils_package import package_install


DEFAULT_SVSM_VTPM_SERIAL_MARKERS = (
    "[SVSM] VTPM: TPM 2.0 Reference Implementation initialized;"
    "Found SVSM vTPM;"
    "TPM2Startup: TPM_RC_SUCCESS"
)

DEFAULT_KERNEL_DRIVER_NAME = "tpm-svsm"


def verify_svsm_vtpm(test, params, vm, session):
    """
    Check SVSM vTPM bring-up via serial log markers, then systemd TPM2
    (skipped when systemd is absent or lacks ``has-tpm2``).
    """
    error_context.context(
        "Reading guest serial console log for SVSM vTPM verification",
        test.log.info,
    )
    serial_log_path = vm.serial_console_log
    if not serial_log_path or not os.path.isfile(serial_log_path):
        test.fail(
            "Serial console log file not found: %s" % serial_log_path)
    with open(serial_log_path, errors="replace") as fd:
        serial_log = fd.read()

    markers_sep = params.get("svsm_vtpm_serial_markers_sep", ";")
    markers_raw = params.get(
        "svsm_vtpm_serial_markers", DEFAULT_SVSM_VTPM_SERIAL_MARKERS
    )
    required_markers = [
        m.strip() for m in markers_raw.split(markers_sep) if m.strip()
    ]
    if not required_markers:
        test.error(
            "No SVSM vTPM serial markers configured "
            "(svsm_vtpm_serial_markers is empty)."
        )

    error_context.context(
        "Searching SVSM vTPM markers in serial console log", test.log.info
    )
    test.log.info(
        f"SVSM vTPM markers to verify in serial log: {required_markers}")
    missing = [m for m in required_markers if m not in serial_log]
    if missing:
        test.fail(
            "SVSM vTPM markers missing from serial console log: "
            f"{missing}. Serial log path: {serial_log_path}"
        )
    test.log.info(
        "All SVSM vTPM serial-log markers found.")

    error_context.context(
        "Userspace: checking systemd-analyze has-tpm2 (if systemd)",
        test.log.info,
    )
    init_check_cmd = "readlink -f /sbin/init"
    init_status, init_output = session.cmd_status_output(
        init_check_cmd, timeout=30)
    init_output = (init_output or "").strip()
    using_systemd = (
        init_status == 0
        and ("systemd" in init_output or "/systemd" in init_output)
    )
    if not using_systemd:
        test.log.info(
            "systemd not detected (init=%r) - skipping "
            "systemd-analyze has-tpm2 check." % init_output
        )
        return
    # has-tpm2 exists from systemd v251 onward
    support_check_cmd = (
        "systemd-analyze --help 2>&1 | grep -qw has-tpm2"
    )
    support_status, _ = session.cmd_status_output(
        support_check_cmd, timeout=30
    )
    if support_status != 0:
        systemd_ver_cmd = "systemctl --version | head -n1"
        _, systemd_ver = session.cmd_status_output(
            systemd_ver_cmd, timeout=15
        )
        test.log.info(
            "'systemd-analyze has-tpm2' not supported by this systemd "
            "(%s) - skipping userspace TPM2 check.",
            (systemd_ver or "").strip(),
        )
        return
    has_tpm2_cmd = "systemd-analyze has-tpm2"
    status, output = session.cmd_status_output(has_tpm2_cmd, timeout=60)
    if status != 0:
        test.fail(
            f"'{has_tpm2_cmd}' failed with status={status}, output='{output}'"
        )
    if output.strip() != "yes":
        test.fail(
            f"'{has_tpm2_cmd}' expected exactly 'yes', got: '{output.strip()}'"
        )
    test.log.info("systemd-analyze has-tpm2 reports: yes")


def _zero_pcr(output):
    """Return True if tpm2_pcrread output looks like an all-zero PCR."""
    digests = re.findall(r"0x[0-9A-Fa-f]+", output)
    if not digests:
        return False
    for d in digests:
        if any(c != "0" for c in d[2:]):
            return False
    return True


def _tpm2_tools_present(session):
    """Return True if tpm2_getcap is on PATH inside the guest."""
    status, _ = session.cmd_status_output(
        "command -v tpm2_getcap >/dev/null 2>&1", timeout=15
    )
    return status == 0


def _ensure_tpm2_tools(test, params, session):
    """Install tpm2-tools in the guest when missing; return availability."""
    if _tpm2_tools_present(session):
        return True

    install_enabled = params.get("svsm_vtpm_install_tpm2_tools", "yes") == "yes"
    pkg = params.get("svsm_vtpm_tpm2_tools_pkg", "tpm2-tools")
    require = params.get("svsm_vtpm_require_tpm2_tools", "no") == "yes"

    if not install_enabled:
        msg = ("tpm2-tools not installed in guest and "
               "svsm_vtpm_install_tpm2_tools=no; skipping functional checks.")
        if require:
            test.fail(msg)
        test.log.warning(msg)
        return False

    error_context.context(
        "Installing %s in guest via avocado-vt package_install" % pkg,
        test.log.info,
    )
    timeout = int(params.get("svsm_vtpm_tpm2_tools_install_timeout", 600))
    installed = False
    try:
        installed = bool(package_install(pkg, session=session, timeout=timeout))
    except Exception as e:
        test.log.warning(
            "package_install(%r) raised: %s", pkg, e
        )

    if installed and _tpm2_tools_present(session):
        test.log.info("tpm2-tools installed successfully (package=%s).", pkg)
        return True

    msg = (
        "Could not install tpm2-tools in guest (package=%r); "
        "tpm2_getcap is still not on PATH. Check guest network/repo "
        "configuration, or override the package name via "
        "svsm_vtpm_tpm2_tools_pkg." % pkg
    )
    if require:
        test.fail(msg)
    test.log.warning(msg + " Skipping tpm2-tools functional checks.")
    return False


def _resolve_attestation_platform(test, params):
    """Return snpguest platform name (milan/genoa/bergamo/turin) for KDS fetch."""
    override = (params.get("svsm_snp_attestation_platform") or "").strip()
    if override:
        return override

    family_id = int(cpu.get_family())
    model_id = int(cpu.get_model())
    dict_cpu = {
        "milan":   (25, 0, 15),
        "genoa":   (25, 16, 31),
        "bergamo": (25, 160, 175),
        "turin":   (26, 0, 31),
    }
    for name, (fam, lo, hi) in dict_cpu.items():
        if family_id == fam and lo <= model_id <= hi:
            return name

    test.cancel(
        "Cannot map host CPU (family=%d, model=%d) to an snpguest "
        " supported platform name milan|genoa|bergamo|turin. "
        "can also be overridden using svsm_snp_attestation_platform"
        % (family_id, model_id)
    )


def _normalize_measurement(raw):
    """Return 96-char lowercase hex SHA-384 digest, or "" if invalid."""
    if not raw:
        return ""
    s = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    return s if re.fullmatch(r"[0-9a-f]{96}", s) else ""


def _compute_expected_measurement(test, params):
    """
    Pin or compute the expected SNP launch digest for the configured IGVM
    (svsm_expected_measurement, else igvmmeasure). Returns "" to skip match.
    """
    pinned = _normalize_measurement(params.get("svsm_expected_measurement"))
    if pinned:
        test.log.info(
            "Using pinned expected SNP measurement from "
            "svsm_expected_measurement (%s).", pinned,
        )
        return pinned

    tool = (params.get("svsm_snp_attestation_measurement_tool") or "").strip()
    if not tool:
        if shutil.which("igvmmeasure"):
            tool = "igvmmeasure"
    if not tool:
        test.log.warning(
            "No svsm_expected_measurement pinned and no measurement tool "
            "found on host (svsm_snp_attestation_measurement_tool unset, "
            "and 'igvmmeasure' is not on PATH). The MEASUREMENT field of "
            "the SNP report will NOT be matched against an expected IGVM "
            "digest; only the report signature + cert chain will be "
            "verified."
        )
        return ""

    igvm_path = params.get("igvm_path", "/usr/share/coconut-svsm")
    igvm_filename = params.get("igvm_filename", "coconut-qemu.igvm")
    igvm_file = os.path.join(igvm_path, igvm_filename)
    if not os.path.isfile(igvm_file):
        test.log.warning(
            "IGVM file %s missing on host; cannot compute expected "
            "measurement. Skipping MEASUREMENT match.", igvm_file,
        )
        return ""

    extra = (params.get("svsm_snp_attestation_measurement_tool_args")
             or "").strip()
    cmd = "%s %s %s measure" % (tool, extra, igvm_file)
    cmd = " ".join(cmd.split())
    timeout = int(params.get("svsm_snp_attestation_measurement_timeout", 60))
    test.log.info("Computing expected SNP measurement: %s", cmd)
    try:
        result = process.run(cmd, timeout=timeout, ignore_status=True,
                             shell=True)
    except Exception as e:
        test.log.warning(
            "Failed to run measurement tool %r: %s. Skipping MEASUREMENT "
            "match.", cmd, e,
        )
        return ""

    if result.exit_status != 0:
        test.log.warning(
            "Measurement tool %r exited with status %d; stderr=%r. "
            "Skipping MEASUREMENT match.",
            cmd, result.exit_status, result.stderr_text[:200],
        )
        return ""

    m = re.search(r"Launch Digest:\s*([0-9A-Fa-f]+)", result.stdout_text)
    digest = _normalize_measurement(m.group(1) if m else "")
    if not digest:
        test.log.warning(
            "Could not parse 'Launch Digest: <96 hex>' from %r output. "
            "Skipping MEASUREMENT match.\nstdout=%s",
            tool, result.stdout_text[:400],
        )
        return ""
    test.log.info("Expected SNP measurement (from %s): %s", tool, digest)
    return digest


def verify_svsm_snp_attestation(test, params, vm, session):
    """Run snpguest attestation workflow (VMPL + optional MEASUREMENT match)."""
    if params.get("svsm_run_snp_attestation", "yes") != "yes":
        test.log.info(
            "svsm_run_snp_attestation=no; skipping SNP attestation check."
        )
        return

    host_platform = _resolve_attestation_platform(test, params)
    test.log.info("snpguest platform name: %s", host_platform)

    error_context.context(
        "Checking /dev/sev-guest character device for attestation",
        test.log.info,
    )
    rc = session.cmd_status("test -c /dev/sev-guest", timeout=15)
    if rc:
        test.fail(
            "/dev/sev-guest is missing in the guest; SNP attestation "
            "requires CONFIG_SEV_GUEST=y in the guest kernel."
        )

    guest_dir = params.get("guest_dir", "/home")
    attestation_script = params.get(
        "attestation_script", "regular_attestation_workflow.sh"
    )
    host_script = params.get(
        "host_script", "sev-snp/%s" % attestation_script
    )
    guest_cmd = params.get(
        "guest_cmd", "%s/%s" % (guest_dir, attestation_script)
    )
    deps_dir = virttest_data_dir.get_deps_dir()
    host_file = os.path.join(deps_dir, host_script)
    if not os.path.isfile(host_file):
        test.fail(
            "Attestation workflow script not found on host: %s "
            "(expected under %s; check that the qemu provider's "
            "sev-snp deps are present)." % (host_file, deps_dir)
        )

    error_context.context(
        "Copying SNP attestation workflow to guest", test.log.info)
    try:
        vm.copy_files_to(host_file, guest_dir)
    except Exception as e:
        test.fail(
            "Failed to copy %s to guest %s: %s"
            % (host_file, guest_dir, str(e))
        )

    sourcebuild = params.get("snpguest_sourcebuild", "1") == "1"
    if sourcebuild:
        error_context.context(
            "Building snpguest from source inside guest", test.log.info)
        snpguest_install_script = params.get(
            "snpguest_install_script", "snpguest_install.sh"
        )
        snpguest_build_location = params.get(
            "snpguest_build_location",
            "sev-snp/%s" % snpguest_install_script,
        )
        snpguest_buildcmd = params.get(
            "snpguest_buildcmd",
            "%s/%s" % (guest_dir, snpguest_install_script),
        )
        snpguest_buildcmd_args = (
            snpguest_buildcmd
            + " "
            + params.get(
                "snpguest_buildcmd_args",
                "--repo https://github.com/virtee/snpguest.git",
            )
        )
        install_snpguest = os.path.join(deps_dir, snpguest_build_location)
        if not os.path.isfile(install_snpguest):
            test.fail(
                "snpguest source-build script not found on host: %s"
                % install_snpguest
            )
        build_timeout = int(
            params.get("svsm_snpguest_build_timeout", 1200)
        )
        try:
            vm.copy_files_to(install_snpguest, guest_dir)
            session.cmd("chmod 755 %s" % snpguest_buildcmd, timeout=30)
            session.cmd(snpguest_buildcmd_args, timeout=build_timeout)
        except Exception as e:
            test.fail(
                "Failed to build snpguest from source in guest: %s"
                % str(e)
            )
    else:
        guest_tool_install = params.get(
            "guest_tool_install", "dnf install -y snpguest"
        )
        error_context.context(
            "Installing snpguest in guest: %s" % guest_tool_install,
            test.log.info,
        )
        try:
            session.cmd_output(guest_tool_install, timeout=300)
        except Exception as e:
            test.fail(
                "Failed to install snpguest via %r: %s"
                % (guest_tool_install, str(e))
            )

    error_context.context(
        "Running SNP attestation workflow in guest", test.log.info)
    try:
        session.cmd_output("chmod 755 %s" % guest_cmd, timeout=30)
    except Exception as e:
        test.fail(
            "Failed to chmod %s in guest: %s" % (guest_cmd, str(e))
        )

    vmpl_arg = params.get("svsm_snp_attestation_vmpl", "2")
    expected_measurement = _compute_expected_measurement(test, params)

    # regular_attestation_workflow.sh: <platform> [<vmpl>] [<measurement>]
    parts = [guest_cmd, host_platform]
    if expected_measurement:
        parts.append(vmpl_arg or "0")
        parts.append(expected_measurement)
    elif vmpl_arg:
        parts.append(vmpl_arg)
    full_cmd = " ".join(parts)

    workflow_timeout = int(
        params.get("svsm_snp_attestation_timeout", 900)
    )
    rc = session.cmd_status(full_cmd, timeout=workflow_timeout)
    if rc:
        test.fail(
            "SNP attestation workflow failed (cmd: %r, host_platform=%s, "
            "vmpl=%r, expected_measurement=%r). Inspect the session log "
            "for details (snpguest report / fetch / verify steps and the "
            "MEASUREMENT match)."
            % (full_cmd, host_platform, vmpl_arg, expected_measurement)
        )
    test.log.info(
        "SNP attestation workflow completed successfully "
        "(host_platform=%s, vmpl=%s, measurement_match=%s).",
        host_platform, vmpl_arg or "default",
        "checked" if expected_measurement else "skipped",
    )


def verify_svsm_vtpm_kernel(test, params, vm, session):
    """Check tpm-svsm driver, /dev/tpm*, and optional tpm2-tools smoke tests."""
    driver_name = params.get(
        "svsm_vtpm_kernel_driver_name", DEFAULT_KERNEL_DRIVER_NAME
    )

    error_context.context(
        "Sysfs: checking %s platform driver is bound" % driver_name,
        test.log.info,
    )
    drv_path = "/sys/bus/platform/drivers/%s" % driver_name
    cmd = (
        "test -d %s && "
        "ls -1 %s/ | grep -Ev '^(bind|unbind|module|uevent)$' || true"
        % (drv_path, drv_path)
    )
    status, output = session.cmd_status_output(cmd, timeout=30)
    if status != 0 or not output.strip():
        test.fail(
            "%s platform driver not bound: %s missing or has no "
            "device. Output=%r" % (driver_name, drv_path, output)
        )
    test.log.info(
        "%s driver bound; sysfs entries: %s", driver_name, output.strip()
    )

    error_context.context(
        "Sysfs: checking /sys/class/tpm/tpm*/device/driver", test.log.info)
    cmd = (
        "for d in /sys/class/tpm/tpm*; do "
        " [ -e \"$d\" ] || continue; "
        " drv=$(readlink -f \"$d/device/driver\" 2>/dev/null); "
        " echo \"$d -> $drv\"; "
        "done"
    )
    status, output = session.cmd_status_output(cmd, timeout=30)
    if status != 0 or driver_name not in (output or ""):
        test.fail(
            "No /sys/class/tpm/tpm* chip is backed by '%s'. "
            "Got:\n%s" % (driver_name, output)
        )
    test.log.info("TPM chip(s) backed by %s:\n%s",
                  driver_name, output.strip())

    error_context.context(
        "Checking /dev/tpm0 and /dev/tpmrm0 exist", test.log.info)
    for dev in ("/dev/tpm0", "/dev/tpmrm0"):
        status, _ = session.cmd_status_output(
            "test -c %s" % dev, timeout=15)
        if status != 0:
            test.fail("%s character device missing in guest." % dev)
    test.log.info("/dev/tpm0 and /dev/tpmrm0 are present.")

    if params.get("svsm_vtpm_run_tpm2_tools", "yes") != "yes":
        test.log.info(
            "svsm_vtpm_run_tpm2_tools=no; skipping tpm2-tools "
            "functional checks."
        )
        return
    if not _ensure_tpm2_tools(test, params, session):
        return

    error_context.context(
        "Functional: tpm2_getcap properties-fixed", test.log.info)
    status, output = session.cmd_status_output(
        "tpm2_getcap properties-fixed", timeout=60
    )
    if status != 0:
        test.fail(
            "tpm2_getcap failed (status=%s):\n%s" % (status, output))
    if "TPM2_PT_" not in output:
        test.fail(
            "tpm2_getcap output looks malformed (no TPM2_PT_*):\n%s"
            % output[:400]
        )
    test.log.info(
        "tpm2_getcap properties-fixed OK (first 8 lines):\n%s",
        "\n".join(output.splitlines()[:8]),
    )

    error_context.context(
        "Functional: tpm2_pcrread sha256:0", test.log.info)
    status, output = session.cmd_status_output(
        "tpm2_pcrread sha256:0", timeout=60
    )
    if status != 0:
        test.fail(
            "tpm2_pcrread sha256:0 failed (status=%s):\n%s"
            % (status, output)
        )
    test.log.info("tpm2_pcrread sha256:0:\n%s", output.strip())
    if _zero_pcr(output):
        msg = (
            "PCR 0 is all zero; firmware did not extend it via the SVSM "
            "vTPM. Either OVMF measured boot is broken or the SVSM vTPM "
            "was not the active TPM at firmware time."
        )
        if params.get("svsm_vtpm_pcr0_must_be_extended", "yes") == "yes":
            test.fail(msg)
        else:
            test.log.warning(msg)

    error_context.context(
        "Functional: tpm2_getrandom 32", test.log.info)
    status, output = session.cmd_status_output(
        "tpm2_getrandom --hex 32; echo", timeout=60
    )
    if status != 0:
        test.fail(
            "tpm2_getrandom failed (status=%s):\n%s" % (status, output))
    rnd = (output or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", rnd):
        test.fail(
            "tpm2_getrandom did not return 32 bytes of hex; "
            "got %d chars: %r" % (len(rnd), rnd)
        )
    test.log.info("tpm2_getrandom returned 32 random bytes: %s", rnd)


@error_context.context_aware
def run(test, params, env):
    """
    Boot an SNP guest with COCONUT-SVSM (IGVM), verify SVSM vTPM, then
    SNP attestation at VMPL2 with optional IGVM MEASUREMENT pinning.

    See qemu/tests/cfg/amd_svsm.cfg for parameters.
    """
    error_context.context("Start SVSM test", test.log.info)
    timeout = params.get_numeric("login_timeout", 240)

    cvm_module_path = params["cvm_module_path"]
    cvm_type = params["vm_secure_guest_type"]
    if os.path.exists(cvm_module_path):
        with open(cvm_module_path) as f:
            output = f.read().strip()
        if output not in params.objects("module_status"):
            test.cancel(
                f"Host support for {cvm_type} capability check failed.")
    else:
        test.cancel(f"Host support for {cvm_type} capability check failed.")

    # IGVM VMSA sets DebugSwap; host needs kvm_amd debug_swap=1
    debug_swap_path = params.get(
        "svsm_debug_swap_path", "/sys/module/kvm_amd/parameters/debug_swap"
    )
    debug_swap_ok_values = params.objects("svsm_debug_swap_status") or [
        "Y", "y", "1",
    ]
    if not os.path.exists(debug_swap_path):
        test.cancel(
            "SVSM precondition not met: %s not found. Either kvm_amd is "
            "not loaded, or this kernel does not expose the debug_swap "
            "module parameter (required: kvm_amd built with "
            "CONFIG_KVM_AMD_SEV and a recent enough kernel). Load with "
            "`modprobe kvm_amd debug_swap=1`." % debug_swap_path
        )
    with open(debug_swap_path) as fh:
        debug_swap_value = fh.read().strip()
    if debug_swap_value not in debug_swap_ok_values:
        test.cancel(
            "SVSM precondition not met: %s = %r (expected one of %r). "
            "The COCONUT-SVSM IGVM bundle requires kvm_amd debug_swap=1; "
            "without it KVM rejects the IGVM-supplied VMSA "
            "(check_sev_features: VMSA contains unsupported "
            "sev_features ... / failed to initialize kvm: Operation not "
            "permitted). Reload kvm_amd with the parameter set, e.g.: "
            "`modprobe -r kvm_amd && modprobe kvm_amd debug_swap=1` "
            "(persist via /etc/modprobe.d/ for reboots)."
            % (debug_swap_path, debug_swap_value, debug_swap_ok_values)
        )
    test.log.info(
        "SVSM precondition OK: %s = %r.", debug_swap_path, debug_swap_value,
    )

    enable_igvm = params.get("enable_igvm") == "yes"
    if not enable_igvm:
        test.cancel(
            "SVSM test requires enable_igvm=yes (IGVM-provided firmware)."
        )
    igvm_path = params.get("igvm_path", "/usr/share/coconut-svsm")
    igvm_filename = params.get("igvm_filename", "coconut-qemu.igvm")
    igvm_file_path = os.path.join(igvm_path, igvm_filename)
    if not os.path.isfile(igvm_file_path):
        test.cancel(
            "IGVM file not found: %s (set igvm_path/igvm_filename to match "
            "your install)." % igvm_file_path
        )
    vm_name = params["main_vm"]
    vm = env.get_vm(vm_name)
    session = None
    try:
        error_context.context("Booting SVSM guest VM", test.log.info)
        try:
            vm.create()
            vm.verify_alive()
        except (aex.TestFail, aex.TestCancel, aex.TestError):
            raise
        except Exception as e:
            test.error("Failed to create VM: %s" % e)
        error_context.context("Logging into VM", test.log.info)
        try:
            session = vm.wait_for_login(timeout=timeout)
        except (aex.TestFail, aex.TestCancel, aex.TestError):
            raise
        except Exception as e:
            test.error("Failed to login to VM: %s" % e)
        verify_dmesg()
        verify_svsm_vtpm(test, params, vm, session)
        verify_svsm_vtpm_kernel(test, params, vm, session)
        verify_svsm_snp_attestation(test, params, vm, session)
    finally:
        if session is not None:
            session.close()
        vm.destroy()
