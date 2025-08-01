import random
import re
import string

from avocado.utils import process
from virttest import (
    data_dir,
    env_process,
    error_context,
    qemu_monitor,
    qemu_qtree,
    storage,
    utils_misc,
)


@error_context.context_aware
def run(test, params, env):
    """
    Check physical resources assigned to KVM virtual machines:
    1) Log into the guest
    2) Verify whether cpu counts ,memory size, nics' model,
       count and drives' format & count, drive_serial, UUID
       reported by the guest OS matches what has been assigned
       to the VM (qemu command line)
    3) Verify all MAC addresses for guest NICs

    :param test: QEMU test object.
    :param params: Dictionary with the test parameters.
    :param env: Dictionary with test environment.
    """

    # Define a function for checking number of hard drivers & NICs
    def check_num(devices, info_cmd, check_str):
        f_fail = []
        expected_num = params.objects(devices).__len__()
        o = ""
        try:
            o = vm.monitor.human_monitor_cmd("info %s " % info_cmd)
        except qemu_monitor.MonitorError as e:
            fail_log = str(e) + "\n"
            fail_log += "info/query monitor command failed (%s)" % info_cmd
            f_fail.append(fail_log)
            test.log.error(fail_log)

        ovmf_fd_num = o.count("%s.fd" % check_str)  # Exclude ovmf fd drive
        actual_num = o.count(check_str) - ovmf_fd_num
        if expected_num != actual_num:
            fail_log = "%s number mismatch:\n" % str(devices)
            fail_log += "    Assigned to VM: %d\n" % expected_num
            fail_log += "    Reported by OS: %d" % actual_num
            f_fail.append(fail_log)
            test.log.error(fail_log)
        return f_fail

    # Define a function for checking hard drives & NICs' model
    def chk_fmt_model(device, fmt_model, info_cmd, regexp):
        f_fail = []
        devices = params.objects(device)
        for chk_device in devices:
            expected = params.object_params(chk_device).get(fmt_model)
            if not expected:
                expected = "rtl8139"
            o = ""
            try:
                o = vm.monitor.human_monitor_cmd("info %s" % info_cmd)
            except qemu_monitor.MonitorError as e:
                fail_log = str(e) + "\n"
                fail_log += "info/query monitor command failed (%s)" % info_cmd
                f_fail.append(fail_log)
                test.log.error(fail_log)

            device_found = re.findall(regexp, o)
            test.log.debug("Found devices: %s", device_found)
            found = False
            for fm in device_found:
                if expected in fm:
                    found = True

            if not found:
                fail_log = "%s model mismatch:\n" % str(device)
                fail_log += "    Assigned to VM: %s\n" % expected
                fail_log += "    Reported by OS: %s" % device_found
                f_fail.append(fail_log)
                test.log.error(fail_log)
        return f_fail

    # Define a function to verify UUID & Serial number
    def verify_device(expect, name, verify_cmd):
        f_fail = []
        if verify_cmd:
            actual = session.cmd_output(verify_cmd)
            if not re.findall(expect, actual, re.I):
                fail_log = "%s mismatch:\n" % name
                fail_log += "    Assigned to VM: %s\n" % expect.upper()
                fail_log += "    Reported by OS: %s" % actual
                f_fail.append(fail_log)
                test.log.error(fail_log)
        return f_fail

    def get_cpu_number(chk_type, chk_timeout):
        """
        Get cpu sockets/cores/threads number.

        :param chk_type: Should be one of 'sockets', 'cores', 'threads'.
        :param chk_timeout: timeout of running chk_cmd.

        :return: Actual number of guest cpu number.
        """
        chk_str = params["mem_chk_re_str"]
        chk_cmd = params.get("cpu_%s_chk_cmd" % chk_type)

        if chk_cmd is None:
            fail_log = "Unknown cpu number checking type: '%s'" % chk_type
            test.log.error(fail_log)
            return -1

        s, output = session.cmd_status_output(chk_cmd, timeout=chk_timeout)
        num = re.findall(chk_str, output)
        if s != 0 or not num:
            fail_log = "Failed to get guest %s number, " % chk_type
            fail_log += "guest output: '%s'" % output
            test.log.error(fail_log)
            return -2

        test.log.info("CPU %s number: %d", chk_type.capitalize(), int(num[-1]))
        return int(num[-1])

    def check_cpu_number(chk_type, actual_n, expected_n):
        """
        Checking cpu sockets/cores/threads number.

        :param chk_type: Should be one of 'sockets', 'cores', 'threads'.
        :param actual_n: Actual number of guest cpu number.
        :param expected_n: Expected number of guest cpu number.

        :return: a list that contains fail report.
        """
        f_fail = []

        if actual_n == -1:
            fail_log = "Unknown cpu number checking type: '%s'" % chk_type
            test.log.error(fail_log)
            f_fail.append(fail_log)
            return f_fail

        if actual_n == -2:
            fail_log = "Failed to get guest %s number." % chk_type
            test.log.error(fail_log)
            f_fail.append(fail_log)
            return f_fail

        test.log.info("CPU %s number check", chk_type.capitalize())

        if actual_n != expected_n:
            fail_log = "%s output mismatch:\n" % chk_type.capitalize()
            fail_log += "    Assigned to VM: '%s'\n" % expected_n
            fail_log += "    Reported by OS: '%s'" % actual_n
            f_fail.append(fail_log)
            test.log.error(fail_log)
            return f_fail

        test.log.debug(
            "%s check pass. Expected: '%s', Actual: '%s'",
            chk_type.capitalize(),
            expected_n,
            actual_n,
        )
        return f_fail

    def verify_machine_type():
        f_fail = []
        cmd = params.get("check_machine_type_cmd")
        fail_log = ""

        if cmd is None:
            return f_fail

        status, actual_mtype = session.cmd_status_output(cmd)
        if status != 0:
            test.error("Failed to get machine type from vm")

        machine_type_cmd = "%s -M ?" % utils_misc.get_qemu_binary(params)
        machine_types = process.system_output(
            machine_type_cmd, ignore_status=True
        ).decode()
        machine_types = machine_types.split(":")[-1]
        machine_type_map = {}
        for machine_type in machine_types.splitlines():
            if not machine_type:
                continue
            type_pair = re.findall(r"([\w\.-]+)\s+([^(]+).*", machine_type)
            if len(type_pair) == 1 and len(type_pair[0]) == 2:
                machine_type_map[type_pair[0][0]] = type_pair[0][1]
            else:
                test.log.warning(
                    "Unexpect output from qemu-kvm -M ?: '%s'", machine_type
                )
        try:
            expect_mtype = machine_type_map[params["machine_type"]].strip()
        except KeyError:
            test.log.warning(
                "Can not find machine type '%s' from qemu-kvm -M ?"
                " output. Skip this test.",
                params["machine_type"],
            )
            return f_fail

        if expect_mtype not in actual_mtype:
            fail_log += "    Assigned to VM: '%s' \n" % expect_mtype
            fail_log += "    Reported by OS: '%s'" % actual_mtype
            f_fail.append(fail_log)
            test.log.error(fail_log)
        else:
            test.log.info(
                "MachineType check pass. Expected: %s, Actual: %s",
                expect_mtype,
                actual_mtype,
            )
        return f_fail

    if params.get("catch_serial_cmd") is not None:
        length = int(params.get("length", "20"))
        id_leng = random.randint(0, length)
        ignore_str = string.punctuation.replace("-", "").replace("_", "")
        drive_serial = utils_misc.generate_random_string(id_leng, ignore_str)
        params["drive_serial"] = drive_serial
        params["start_vm"] = "yes"

        vm = params["main_vm"]
        vm_params = params.object_params(vm)
        env_process.preprocess_vm(test, vm_params, env, vm)
        vm = env.get_vm(vm)
    else:
        vm = env.get_vm(params["main_vm"])

    vm.verify_alive()
    timeout = int(params.get("login_timeout", 360))
    chk_timeout = int(params.get("chk_timeout", 240))

    error_context.context("Login to the guest", test.log.info)
    session = vm.wait_for_login(timeout=timeout)

    qtree = qemu_qtree.QtreeContainer()
    try:
        qtree.parse_info_qtree(vm.monitor.info("qtree"))
    except AttributeError:  # monitor doesn't support info qtree
        qtree = None

    test.log.info("Starting physical resources check test")
    test.log.info(
        "Values assigned to VM are the values we expect "
        "to see reported by the Operating System"
    )
    # Define a failure counter, as we want to check all physical
    # resources to know which checks passed and which ones failed
    n_fail = []

    # We will check HDs with the image name
    image_name = storage.get_image_filename(params, data_dir.get_data_dir())

    # Check cpu count
    error_context.context("CPU count check", test.log.info)
    actual_cpu_nr = vm.get_cpu_count()
    cpu_cores_num = get_cpu_number("cores", chk_timeout)
    cpu_lp_num = get_cpu_number("logical_processors", chk_timeout)
    cpu_threads_num = get_cpu_number("threads", chk_timeout)
    cpu_sockets_num = get_cpu_number("sockets", chk_timeout)

    if (
        (params.get("os_type") == "windows")
        and cpu_cores_num > 0
        and cpu_lp_num > 0
        and cpu_sockets_num > 0
    ):
        actual_cpu_nr = cpu_lp_num * cpu_sockets_num
        cpu_threads_num = cpu_lp_num / cpu_cores_num

    if vm.cpuinfo.smp != actual_cpu_nr:
        fail_log = "CPU count mismatch:\n"
        fail_log += "    Assigned to VM: %s \n" % vm.cpuinfo.smp
        fail_log += "    Reported by OS: %s" % actual_cpu_nr
        n_fail.append(fail_log)
        test.log.error(fail_log)

    n_fail.extend(check_cpu_number("cores", cpu_cores_num, vm.cpuinfo.cores))

    n_fail.extend(check_cpu_number("threads", cpu_threads_num, vm.cpuinfo.threads))

    n_fail.extend(check_cpu_number("sockets", cpu_sockets_num, vm.cpuinfo.sockets))

    # Check the cpu vendor_id
    expected_vendor_id = params.get("cpu_model_vendor")
    cpu_vendor_id_chk_cmd = params.get("cpu_vendor_id_chk_cmd")
    if expected_vendor_id and cpu_vendor_id_chk_cmd:
        output = session.cmd_output(cpu_vendor_id_chk_cmd)

        if expected_vendor_id not in output:
            fail_log = "CPU vendor id check failed.\n"
            fail_log += "    Assigned to VM: '%s'\n" % expected_vendor_id
            fail_log += "    Reported by OS: '%s'" % output
            n_fail.append(fail_log)
            test.log.error(fail_log)

    # Check memory size
    error_context.context("Memory size check", test.log.info)
    expected_mem = int(params["mem"])
    vm_mem_limit = params.get("vm_mem_limit")
    actual_mem = vm.get_memory_size()
    if vm_mem_limit:
        error_context.context("Skip memory checking %s" % vm_mem_limit, test.log.info)
    elif actual_mem != expected_mem:
        fail_log = "Memory size mismatch:\n"
        fail_log += "    Assigned to VM: %s\n" % expected_mem
        fail_log += "    Reported by OS: %s\n" % actual_mem
        n_fail.append(fail_log)
        test.log.error(fail_log)

    error_context.context("Hard drive count check", test.log.info)
    f_fail = check_num("images", "block", image_name)
    n_fail.extend(f_fail)

    error_context.context("NIC count check", test.log.info)
    f_fail = check_num("nics", "network", "model=")
    n_fail.extend(f_fail)

    error_context.context("NICs model check", test.log.info)
    f_fail = chk_fmt_model("nics", "nic_model", "network", "model=(.*),")
    n_fail.extend(f_fail)

    if qtree is not None:
        error_context.context("Images params check", test.log.info)
        test.log.debug("Found devices: %s", params.objects("images"))
        qdisks = qemu_qtree.QtreeDisksContainer(qtree.get_nodes())
        disk_errors = sum(qdisks.parse_info_block(vm.monitor.info_block()))
        disk_errors += qdisks.generate_params()
        disk_errors += qdisks.check_disk_params(params)
        if disk_errors:
            disk_errors = (
                "Images check failed with %s errors, "
                "check the log for details" % disk_errors
            )
            test.log.error(disk_errors)
            n_fail.append("\n".join(qdisks.errors))
    else:
        test.log.info(
            "Images check param skipped (qemu monitor doesn't support 'info qtree')"
        )

    error_context.context("Network card MAC check", test.log.info)
    o = ""
    try:
        o = vm.monitor.human_monitor_cmd("info network")
    except qemu_monitor.MonitorError as e:
        fail_log = str(e) + "\n"
        fail_log += "info/query monitor command failed (network)"
        n_fail.append(fail_log)
        test.log.error(fail_log)
    found_mac_addresses = re.findall(r"macaddr=(\S+)", o)
    test.log.debug("Found MAC adresses: %s", found_mac_addresses)

    num_nics = len(params.objects("nics"))
    for nic_index in range(num_nics):
        mac = vm.get_mac_address(nic_index)
        if mac.lower() not in found_mac_addresses:
            fail_log = "MAC address mismatch:\n"
            fail_log += "    Assigned to VM (not found): %s" % mac
            n_fail.append(fail_log)
            test.log.error(fail_log)

    error_context.context("UUID check", test.log.info)
    if vm.get_uuid():
        f_fail = verify_device(vm.get_uuid(), "UUID", params.get("catch_uuid_cmd"))
        n_fail.extend(f_fail)

    error_context.context("Hard Disk serial number check", test.log.info)
    catch_serial_cmd = params.get("catch_serial_cmd")
    f_fail = verify_device(params.get("drive_serial"), "Serial", catch_serial_cmd)
    n_fail.extend(f_fail)

    error_context.context("Machine Type Check", test.log.info)
    f_fail = verify_machine_type()
    n_fail.extend(f_fail)

    if n_fail:
        session.close()
        test.fail(
            "Physical resources check test "
            "reported %s failures:\n%s" % (len(n_fail), "\n".join(n_fail))
        )

    session.close()
