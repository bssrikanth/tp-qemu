from virttest import env_process, utils_package, utils_test
from virttest.staging import utils_memory


def run(test, params, env):
    """
    Boot VMs and run kernel compile inside VM parallel.

    1) Boot up VMs:
       Every VM has 4G vmem, the total vmem of VMs' are
       $overcommit times as host's mem.
    2) Launch kernel compile inside every guest.

    :param test: QEMU test object.
    :param params: Dictionary with the test parameters.
    :param env: Dictionary with test environment.
    """

    def kernelcompile(session, vm_name):
        vm = env.get_vm(vm_name)
        ip = vm.get_address()
        path = params.get("download_url")
        test.log.info("kernel path = %s", path)
        get_kernel_cmd = "wget %s" % path
        install_status = utils_package.package_install("wget", session, timeout=60)
        if not install_status:
            test.error("Failed to install wget.")
        try:
            status, output = session.cmd_status_output(
                get_kernel_cmd, timeout=2400, safe=True
            )
            if status != 0:
                test.log.error(output)
                test.fail("Fail to download the kernel in %s" % vm_name)
            else:
                test.log.info("Completed download the kernel src in %s", vm_name)
            test_cmd = params.get("test_cmd")
            status, output = session.cmd_status_output(test_cmd, timeout=1200)
            if status != 0:
                test.log.error(output)
        finally:
            status, _ = utils_test.ping(ip, count=10, timeout=30)
            if status != 0:
                test.fail("vm no response, pls check serial log")

    over_c = float(params.get("overcommit", 1.5))
    guest_number = int(params.get("guest_number", "1"))

    if guest_number < 1:
        test.log.warning(
            "At least boot up one guest for this test, set up guest number to 1"
        )
        guest_number = 1

    for tag in range(1, guest_number):
        params["vms"] += " stress_guest_%s" % tag

    mem_host = utils_memory.memtotal() / 1024
    vmem = int(mem_host * over_c / guest_number)

    if vmem < 256:
        test.cancel(
            "The memory size set for guest is too small."
            " Please try less than %s guests"
            " in this host." % guest_number
        )
    params["mem"] = vmem
    params["start_vm"] = "yes"
    login_timeout = int(params.get("login_timeout", 360))

    env_process.preprocess(test, params, env)

    sessions_info = []
    for vm_name in params["vms"].split():
        vm = env.get_vm(vm_name)
        vm.verify_alive()
        session = vm.wait_for_login(timeout=login_timeout)
        if not session:
            test.fail("Could not log into guest %s" % vm_name)

        sessions_info.append([session, vm_name])

    # run kernel compile in vms
    try:
        test.log.info("run kernel compile in vms")
        bg_threads = []
        for session_info in sessions_info:
            session = session_info[0]
            vm_name = session_info[1]
            bg_thread = utils_test.BackgroundTest(kernelcompile, (session, vm_name))
            bg_thread.start()
            bg_threads.append(bg_thread)

        completed = False
        while not completed:
            completed = True
            for bg_thread in bg_threads:
                if bg_thread.is_alive():
                    completed = False
    finally:
        try:
            for bg_thread in bg_threads:
                if bg_thread:
                    bg_thread.join()
        finally:
            for session_info in sessions_info:
                session_info[0].close()
