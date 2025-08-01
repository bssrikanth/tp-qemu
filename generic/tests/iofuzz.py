import random
import re

import aexpect
from virttest import data_dir, qemu_storage, qemu_vm, storage, virt_vm


def run(test, params, env):
    """
    KVM iofuzz test:
    1) Log into a guest
    2) Enumerate all IO port ranges through /proc/ioports
    3) On each port of the range:
        * Read it
        * Write 0 to it
        * Write a random value to a random port on a random order

    If the guest SSH session hangs, the test detects the hang and the guest
    is then rebooted. The test fails if we detect the qemu process to terminate
    while executing the process.

    :param test: kvm test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    def qemu_img_check():
        """
        Check guest disk image, and backup image when error occured
        """
        params["backup_image_on_check_error"] = "yes"
        base_dir = data_dir.get_data_dir()
        image_name = storage.get_image_filename(params, base_dir)
        image = qemu_storage.QemuImg(params, base_dir, image_name)
        image.check_image(params, base_dir)

    def outb(session, port, data):
        """
        Write data to a given port.

        :param session: SSH session stablished to a VM
        :param port: Port where we'll write the data
        :param data: Integer value that will be written on the port. This
                value will be converted to octal before its written.
        """
        test.log.debug("outb(0x%x, 0x%x)", port, data)
        outb_cmd = "echo -e '\\%s' | dd of=/dev/port seek=%d bs=1 count=1" % (
            oct(data),
            port,
        )
        try:
            session.cmd(outb_cmd)
        except aexpect.ShellError as err:
            test.log.debug(err)

    def inb(session, port):
        """
        Read from a given port.

        :param session: SSH session stablished to a VM
        :param port: Port where we'll read data
        """
        test.log.debug("inb(0x%x)", port)
        inb_cmd = "dd if=/dev/port seek=%d of=/dev/null bs=1 count=1" % port
        try:
            session.cmd(inb_cmd)
        except aexpect.ShellError as err:
            test.log.debug(err)

    def fuzz(test, session, inst_list):
        """
        Executes a series of read/write/randwrite instructions.

        If the guest SSH session hangs, an attempt to relogin will be made.
        If it fails, the guest will be reset. If during the process the VM
        process abnormally ends, the test fails.

        :param inst_list: List of instructions that will be executed.
        :raise error.TestFail: If the VM process dies in the middle of the
                fuzzing procedure.
        """
        for wr_op, operand in inst_list:
            if wr_op == "read":
                inb(session, operand[0])
            elif wr_op == "write":
                outb(session, operand[0], operand[1])
            else:
                test.error("Unknown command %s" % wr_op)

            if not session.is_responsive():
                test.log.debug("Session is not responsive")
                try:
                    vm.verify_alive()
                except qemu_vm.QemuSegFaultError as err:
                    test.fail("Qemu crash, error info: %s" % err)
                except virt_vm.VMDeadKernelCrashError as err:
                    test.fail("Guest kernel crash, info: %s" % err)
                else:
                    test.log.warning("Guest is not alive during test")

                if vm.process.is_alive():
                    test.log.debug("VM is alive, try to re-login")
                    try:
                        session = vm.wait_for_login(timeout=10)
                    except Exception:
                        test.log.debug("Could not re-login, reboot the guest")
                        qemu_img_check()
                        session = vm.reboot(method="system_reset")
                else:
                    test.fail("VM has quit abnormally during %s: %s" % (wr_op, operand))

    login_timeout = float(params.get("login_timeout", 240))
    vm = env.get_vm(params["main_vm"])
    vm.verify_alive()
    session = vm.wait_for_login(timeout=login_timeout)

    try:
        ports = {}
        o_random = random.SystemRandom()

        test.log.info("Enumerate guest devices through /proc/ioports")
        ioports = session.cmd_output("cat /proc/ioports")
        test.log.debug(ioports)
        devices = re.findall(r"(\w+)-(\w+)\ : (.*)", ioports)

        skip_devices = params.get("skip_devices", "")
        fuzz_count = int(params.get("fuzz_count", 10))

        for beg, end, name in devices:
            ports[(int(beg, base=16), int(end, base=16))] = name.strip()

        for beg, end in ports.keys():
            name = ports[(beg, end)]
            if name in skip_devices:
                test.log.info("Skipping device %s", name)
                continue

            test.log.info("Fuzzing %s, port range 0x%x-0x%x", name, beg, end)
            inst = []

            # Read all ports of the range
            for port in range(beg, end + 1):
                inst.append(("read", [port]))

            # Write 0 to all ports of the range
            for port in range(beg, end + 1):
                inst.append(("write", [port, 0]))

            # Write random values to random ports of the range
            for _ in range(fuzz_count * (end - beg + 1)):
                inst.append(
                    ("write", [o_random.randint(beg, end), o_random.randint(0, 255)])
                )

            fuzz(test, session, inst)
        vm.verify_alive()
    finally:
        session.close()
