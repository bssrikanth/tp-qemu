import os
import re
import shlex

from avocado.utils import cpu, process
from avocado.utils import path as utils_path
from avocado.utils.path import CmdNotFoundError
from virttest import data_dir as virttest_data_dir
from virttest import error_context
from virttest.utils_misc import verify_dmesg
from virttest.vt_utils import cpu as vt_cpu


def _normalize_measurement(raw):
    """Return 96-char lowercase hex SHA-384 digest, or "" if invalid."""
    if not raw:
        return ""
    s = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    return s if re.fullmatch(r"[0-9a-f]{96}", s) else ""


_HOST_CPU_TO_VCPU_TYPE = {
    "milan": "EPYC-Milan",
    "genoa": "EPYC-Genoa",
    "turin": "EPYC-Turin",
}


def _cpuinfo_model():
    """Numeric model field from /proc/cpuinfo (first logical CPU)."""
    info = vt_cpu.get_cpu_info()
    if not info or "model" not in info[0]:
        raise OSError("The cpu model was NOT found in /proc/cpuinfo!")
    return int(info[0]["model"])


def _guest_qemu_cpu_model(params, vm):
    """QEMU guest -cpu model (from vm.cpuinfo after create, else params)."""
    if vm is not None:
        try:
            guest = (vm.cpuinfo.model or "").strip()
            if guest:
                return guest
        except AttributeError:
            pass
    return (params.get("cpu_model") or "").strip()


def _measure_tool_supports_vcpu_type(tool, vcpu_type):
    """Return True if *tool* lists *vcpu_type* among --vcpu-type choices."""
    try:
        result = process.run(
            "%s --help" % shlex.quote(tool),
            timeout=30, ignore_status=True, shell=True,
        )
    except Exception:
        return False
    if result.exit_status != 0:
        return False
    return vcpu_type in (result.stdout_text or "")


def _resolve_vcpu_args(test, params, host_cpu_model, measure_tool=None,
                        vm=None):
    """
    Build sev-snp-measure ``--vcpu-*`` args for guest vCPU identity.

    Order: snp_measure_vcpu_type, guest cpu_model, EPYC-* by platform,
    else cpuinfo family/model/stepping. Returns None if unresolved.
    """
    explicit = (params.get("snp_measure_vcpu_type") or "").strip()
    if explicit:
        test.log.info(
            "Using snp_measure_vcpu_type=%s (cfg override).", explicit,
        )
        return ["--vcpu-type %s" % explicit]

    guest_cpu = _guest_qemu_cpu_model(params, vm)
    if guest_cpu and guest_cpu != "host":
        if (measure_tool
                and not _measure_tool_supports_vcpu_type(measure_tool,
                                                          guest_cpu)):
            test.log.warning(
                "Installed sev-snp-measure does not support guest "
                "cpu_model=%s as --vcpu-type; falling back to other "
                "resolution paths.", guest_cpu,
            )
        else:
            test.log.info(
                "Using guest QEMU cpu_model=%s as sev-snp-measure "
                "--vcpu-type.", guest_cpu,
            )
            return ["--vcpu-type %s" % guest_cpu]

    friendly = _HOST_CPU_TO_VCPU_TYPE.get(host_cpu_model)
    if friendly:
        if (measure_tool
                and not _measure_tool_supports_vcpu_type(measure_tool,
                                                          friendly)):
            test.log.warning(
                "Installed sev-snp-measure does not support --vcpu-type "
                "%s; falling back to --vcpu-family/--vcpu-model/"
                "--vcpu-stepping.", friendly,
            )
        else:
            test.log.info(
                "Mapping host_cpu_model=%s to sev-snp-measure "
                "--vcpu-type=%s (guest cpu_model=%r).",
                host_cpu_model, friendly, guest_cpu or "host",
            )
            return ["--vcpu-type %s" % friendly]

    try:
        fam = int(vt_cpu.get_cpu_family())
        mod = _cpuinfo_model()
        step = int(vt_cpu.get_cpu_stepping())
        phys_name = vt_cpu.get_cpu_model_name()
    except (OSError, ValueError, TypeError, NotImplementedError) as e:
        test.log.warning(
            "Could not read guest vCPU family/model/stepping (%s). Set "
            "snp_measure_vcpu_type to one of EPYC-Milan / EPYC-Genoa / "
            "EPYC-Turin / EPYC-Milan-v2 / etc. to pin the vCPU identity for "
            "sev-snp-measure.", e,
        )
        return None
    test.log.info(
        "Auto-derived guest vCPU identity: family=%d, model=%d, "
        "stepping=%d (host_cpu_model=%s, physical=%r, guest "
        "cpu_model=%r).",
        fam, mod, step, host_cpu_model, phys_name, guest_cpu or "host",
    )
    return [
        "--vcpu-family %d" % fam,
        "--vcpu-model %d" % mod,
        "--vcpu-stepping %d" % step,
    ]


def _ensure_sev_snp_measure(test, params):
    """Locate or autoinstall sev-snp-measure; return path/name or ""."""
    pinned = (params.get("snp_attestation_measurement_tool") or "").strip()
    if pinned:
        return pinned
    try:
        return utils_path.find_command(
            "sev-snp-measure", default=None, check_exec=True,
        )
    except CmdNotFoundError:
        test.log.info(
            "sev-snp-measure not found in PATH or common bin paths; "
            "proceeding with autoinstall (set snp_measure_autoinstall=no "
            "to disable, or pin snp_attestation_measurement_tool to an "
            "absolute path)."
        )

    autoinstall = params.get_boolean("snp_measure_autoinstall", True)
    if not autoinstall:
        return ""

    install_script_rel = params.get(
        "snp_measure_install_script", "sev-snp/sev_snp_measure_install.sh"
    )
    deps_dir = virttest_data_dir.get_deps_dir()
    install_script = os.path.join(deps_dir, install_script_rel)
    if not os.path.isfile(install_script):
        test.log.warning(
            "snp_measure_autoinstall=yes but installer script not found "
            "on host: %s. Skipping autoinstall.", install_script,
        )
        return ""

    repo = params.get(
        "snp_measure_install_repo",
        "https://github.com/virtee/sev-snp-measure.git",
    )
    tag = (params.get("snp_measure_install_tag") or "").strip()
    branch = (params.get("snp_measure_install_branch") or "").strip()
    install_timeout = params.get_numeric("snp_measure_install_timeout", 600)
    extra = (params.get("snp_measure_install_args") or "").strip()
    if tag:
        ref_args = "--tag %s" % shlex.quote(tag)
        ref_label = "tag=%s" % tag
    elif branch:
        ref_args = "--branch %s" % shlex.quote(branch)
        ref_label = "branch=%s" % branch
    else:
        ref_args = ""
        ref_label = "default"
    cmd = "bash %s --repo %s %s %s" % (
        shlex.quote(install_script), shlex.quote(repo), ref_args, extra,
    )
    cmd = " ".join(cmd.split())

    error_context.context(
        "Installing sev-snp-measure on host (%s @ %s)" % (repo, ref_label),
        test.log.info,
    )
    test.log.info("Running host-side installer: %s", cmd)
    try:
        result = process.run(cmd, timeout=install_timeout,
                             ignore_status=True, shell=True)
    except Exception as e:
        test.log.warning(
            "Failed to run sev-snp-measure installer %r: %s. Skipping "
            "MEASUREMENT match.", cmd, e,
        )
        return ""
    if result.exit_status != 0:
        test.log.warning(
            "sev-snp-measure installer exited with status %d.\n"
            "stdout (tail): %s\nstderr (tail): %s\n"
            "Skipping MEASUREMENT match. Re-run the installer manually "
            "to debug: %s",
            result.exit_status,
            (result.stdout_text or "")[-600:],
            (result.stderr_text or "")[-600:],
            cmd,
        )
        return ""

    try:
        found = utils_path.find_command(
            "sev-snp-measure", default=None, check_exec=True,
        )
    except CmdNotFoundError:
        test.log.warning(
            "Installer reported success but 'sev-snp-measure' is not "
            "discoverable in common bin paths (PATH + /usr/local/{s,}bin, "
            "/usr/{s,}bin, /sbin, /bin, /usr/libexec). Check %s for an "
            "unexpected install location. Skipping MEASUREMENT match.",
            install_script,
        )
        return ""
    test.log.info(
        "sev-snp-measure installed successfully (found at %s).", found,
    )
    return found


def _compute_expected_measurement_snp(test, params, vm, host_cpu_model):
    """
    Pin or compute expected SNP launch digest (cfg or sev-snp-measure).

    Returns "" to skip MEASUREMENT match in the attestation workflow.
    """
    pinned = _normalize_measurement(params.get("snp_expected_measurement"))
    if pinned:
        test.log.info(
            "Using pinned expected SNP measurement from "
            "snp_expected_measurement (%s).", pinned,
        )
        return pinned

    tool = _ensure_sev_snp_measure(test, params)
    if not tool:
        test.log.warning(
            "No snp_expected_measurement pinned and no usable measurement "
            "tool on host (sev-snp-measure not on PATH and autoinstall "
            "either disabled or failed). The MEASUREMENT field of the "
            "SNP report will NOT be matched against an expected launch "
            "digest; only the report signature + cert chain will be "
            "verified. Set snp_measure_autoinstall=yes (default) to "
            "build it from %s, pin snp_attestation_measurement_tool to "
            "an absolute path, or pin snp_expected_measurement to a "
            "known-good digest.",
            params.get(
                "snp_measure_install_repo",
                "https://github.com/virtee/sev-snp-measure",
            ),
        )
        return ""

    ovmf = (params.get("snp_measure_ovmf")
            or params.get("bios_path") or "").strip()
    if not ovmf:
        test.log.warning(
            "Neither snp_measure_ovmf nor bios_path is set; cannot tell "
            "sev-snp-measure which OVMF blob to hash. Skipping "
            "MEASUREMENT match."
        )
        return ""
    if not os.path.isfile(ovmf):
        test.log.warning(
            "OVMF binary %s missing on host; cannot compute expected "
            "SNP measurement. Skipping MEASUREMENT match.", ovmf,
        )
        return ""

    try:
        vcpus = int(vm.cpuinfo.smp)
    except (AttributeError, TypeError, ValueError) as e:
        test.log.warning(
            "Could not read vm.cpuinfo.smp (%s); falling back to "
            "vcpus=1. Skipping MEASUREMENT match if the digest "
            "diverges.", e,
        )
        return ""

    vcpu_args = _resolve_vcpu_args(test, params, host_cpu_model,
                                   measure_tool=tool, vm=vm)
    if vcpu_args is None:
        return ""

    optional_args = []
    guest_features = (params.get("snp_measure_guest_features") or "").strip()
    if guest_features:
        optional_args.append("--guest-features %s" % shlex.quote(guest_features))
    for cfg_key, cli_flag in (
        ("snp_measure_kernel", "--kernel"),
        ("snp_measure_initrd", "--initrd"),
        ("snp_measure_append", "--append"),
    ):
        val = (params.get(cfg_key) or "").strip()
        if val:
            optional_args.append("%s %s" % (cli_flag, shlex.quote(val)))

    extra = (params.get("snp_attestation_measurement_tool_args") or "").strip()

    cmd_parts = [
        shlex.quote(tool), "--mode snp", "--vcpus %d" % vcpus,
        " ".join(vcpu_args), "--ovmf %s" % shlex.quote(ovmf),
        " ".join(optional_args), extra,
    ]
    cmd = " ".join(p for p in cmd_parts if p).strip()
    timeout = params.get_numeric("snp_attestation_measurement_timeout", 60)
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
            cmd, result.exit_status, result.stderr_text[:400],
        )
        return ""

    stdout = result.stdout_text or ""
    m = re.search(r"Launch Digest:\s*([0-9A-Fa-f]{96})", stdout)
    if m:
        digest = _normalize_measurement(m.group(1))
    else:
        candidates = re.findall(r"[0-9A-Fa-f]{96,}", stdout)
        digest = _normalize_measurement(candidates[0]) if candidates else ""
    if not digest:
        test.log.warning(
            "Could not parse a 96-hex-char SHA-384 from %r output. "
            "Skipping MEASUREMENT match.\nstdout=%s",
            tool, stdout[:400],
        )
        return ""
    test.log.info("Expected SNP measurement (from %s): %s", tool, digest)
    return digest


@error_context.context_aware
def run(test, params, env):
    """
    Qemu snp basic test on Milan and above host:
    1. Check host snp capability
    2. Boot snp VM
    3. Verify snp enabled in guest
    4. Check snp qmp cmd and policy
    5. Run attestation with optional launch measurement.

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
    single_socket = params.get_boolean("single_socket", False)
    if single_socket:
        res = cpu.lscpu()
        if int(res["sockets"]) != 1:
            test.cancel("Host cpu has more than 1 socket, skip the case.")

    family_id = int(cpu.get_family())
    model_id = int(cpu.get_model())
    dict_cpu = {
        "milan": [25, 0, 15],
        "genoa": [25, 16, 31],
        "bergamo": [25, 160, 175],
        "turin": [26, 0, 31],
    }
    host_cpu_model = None
    for platform, values in dict_cpu.items():
        if values[0] == family_id:
            if model_id >= values[1] and model_id <= values[2]:
                host_cpu_model = platform
    if not host_cpu_model:
        test.cancel("Unsupported platform. Requires milan or above.")
    test.log.info("Detected platform: %s", host_cpu_model)
    vm_name = params["main_vm"]
    vm = env.get_vm(vm_name)
    vm.create()
    vm.verify_alive()
    session = vm.wait_for_login(timeout=timeout)
    verify_dmesg()
    test.log.info("Checking for SNP attestation support in guest")
    rc_code = session.cmd_status("test -c /dev/sev-guest")
    if rc_code:
        test.cancel(
            "Error: Unable to find /dev/sev-guest. Guest kernel support for "
            "SNP attestation is missing."
        )
    vm_policy_int = params.get_numeric("vm_sev_policy", 0x30000)
    guest_check_cmd = params["snp_guest_check"]
    sev_guest_info = vm.monitor.query_sev()
    if sev_guest_info["snp-policy"] != vm_policy_int:
        test.fail(
            "QMP snp policy doesn't match cfg: vm_sev_policy=0x%x (%d), "
            "QMP snp-policy=%d (0x%x). Make sure 'vm_sev_policy' is set "
            "in cfg for this variant -- vm_secure_guest_object_options "
            "'policy=' is overwritten by avocado-vt's vm_sev_policy "
            "default in qemu_devices/qcontainer.py:_gen_snp_obj_props()."
            % (vm_policy_int, vm_policy_int, sev_guest_info["snp-policy"],
               sev_guest_info["snp-policy"])
        )
    try:
        session.cmd_output(guest_check_cmd, timeout=240)
    except Exception as e:
        test.fail("Guest snp verify fail: %s" % str(e))
    else:
        error_context.context("Start to do attestation", test.log.info)
        guest_dir = params["guest_dir"]
        host_script = params["host_script"]
        guest_cmd = params["guest_cmd"]
        deps_dir = virttest_data_dir.get_deps_dir()
        host_file = os.path.join(deps_dir, host_script)
        try:
            vm.copy_files_to(host_file, guest_dir)
            if params.get("snpguest_sourcebuild", "0") == "1":
                snpguest_build_location = params["snpguest_build_location"]
                snpguest_buildcmd = params["snpguest_buildcmd"]
                snpguest_buildcmd_args = (
                    snpguest_buildcmd + " " + params.get("snpguest_buildcmd_args", "")
                )
                install_snpguest = os.path.join(deps_dir, snpguest_build_location)
                vm.copy_files_to(install_snpguest, guest_dir)
                session.cmd("chmod 755 %s" % snpguest_buildcmd)
                session.cmd(snpguest_buildcmd_args, timeout=360)
            else:
                session.cmd_output(params["guest_tool_install"], timeout=240)
            session.cmd_output("chmod 755 %s" % guest_cmd)
        except Exception as e:
            test.fail("Guest test preparation fail: %s" % str(e))
        expected_measurement = _compute_expected_measurement_snp(
            test, params, vm, host_cpu_model,
        )
        if (not expected_measurement
                and params.get_boolean("snp_measurement_required", False)):
            test.fail(
                "snp_measurement_required=yes but no expected SNP "
                "MEASUREMENT could be resolved (no snp_expected_measurement "
                "pinned and the host-side sev-snp-measure tool produced "
                "no usable digest). Refusing to fall back to "
                "signature-only verification. See preceding warnings "
                "for the specific failure reason."
            )
        # regular_attestation_workflow.sh: <platform> [<vmpl>] [<measurement>]
        if expected_measurement:
            full_cmd = '%s %s "" %s' % (
                guest_cmd, host_cpu_model, expected_measurement,
            )
        else:
            full_cmd = "%s %s" % (guest_cmd, host_cpu_model)
        s = session.cmd_status(full_cmd, timeout=360)
        if s:
            test.fail(
                "Guest script error (cmd: %r, host_cpu_model=%s, "
                "expected_measurement=%r). Check the session logs for "
                "further details (snpguest report / fetch / verify steps "
                "and the MEASUREMENT match)."
                % (full_cmd, host_cpu_model, expected_measurement)
            )
        test.log.info(
            "SNP attestation workflow completed successfully "
            "(host_cpu_model=%s, measurement_match=%s, required=%s).",
            host_cpu_model,
            "checked" if expected_measurement else "skipped",
            params.get_boolean("snp_measurement_required", False),
        )
    finally:
        session.close()
        vm.destroy()
