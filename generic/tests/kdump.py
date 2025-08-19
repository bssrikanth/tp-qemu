import logging
import os
import re
import time

from avocado.utils import process
from virttest import (env_process, error_context, utils_conn, utils_misc,
                      utils_net, utils_package)

LOG_JOB = logging.getLogger("avocado.test")


@error_context.context_aware
def preprocess_kdump(test, vm, timeout):
    """
    Backup /etc/kdump.conf file before trigger crash.

    :param timeout: Timeout in seconds
    """
    os_type = vm.get_distro().lower()
    kdump_cfg_path = vm.params.get(
        "kdump_cfg_path", "/etc/kdump.conf" if os_type == "rhel" else "/etc/default/kdump-tools")
    auth_key_path = vm.params.get("auth_key_path")
    backup_key_cmd = "/bin/cp -f %s %s-bk" % (auth_key_path, auth_key_path)
    cp_kdumpcf_cmd = "/bin/cp -f %s %s-bk" % (kdump_cfg_path, kdump_cfg_path)
    cp_kdumpcf_cmd = vm.params.get("cp_kdumpcf_cmd", cp_kdumpcf_cmd)
    session = vm.wait_for_login(timeout=timeout)
    if os_type == "rhel":
        pkg_mgr = utils_package.package_manager(session, "kexec-tools")
        if not pkg_mgr.is_installed("kexec-tools"):
            if not pkg_mgr.install():
                test.cancel("kexec-tools package install failed")
    elif os_type == "ubuntu":
        pkg_mgr = utils_package.package_manager(session, "kdump-tools")
        if not pkg_mgr.is_installed("kdump-tools"):
            test.log.info("Configuring debconf for kdump-tools")
            session.cmd(
                "echo 'kdump-tools kdump-tools/use_kdump boolean true' | debconf-set-selections")
            if not pkg_mgr.install():
                test.cancel("kdump-tools package installation failed")
        status, output = session.cmd_status_output(f"test -f {kdump_cfg_path}")
        if status != 0:
            test.log.error(
                f"{kdump_cfg_path} not found after kdump-tools installation: {output}")
            test.error("Failed to find kdump-tools configuration file")
    else:
        test.cancel("Unsupported guest distro")
    if auth_key_path:
        create_key_cmd = "/bin/touch %s" % auth_key_path
        if not os.path.exists("/root/.ssh"):
            process.run("mkdir /root/.ssh", shell=True)
        test.log.info("Create authorized_keys file if it not existed.")
        process.run(create_key_cmd, shell=True)
        test.log.info("Backup authorized_keys file.")
        process.run(backup_key_cmd, shell=True)
    test.log.info("Backup kdump.conf file.")
    status, output = session.cmd_status_output(cp_kdumpcf_cmd)

    if status != 0:
        test.log.error(output)
        test.error("Fail to backup the kdump.conf")

    session.close()


@error_context.context_aware
def postprocess_kdump(test, vm, timeout):
    """
    Restore /etc/kdump.conf file after trigger crash.

    :param timeout: Timeout in seconds
    """
    os_type = vm.get_distro().lower()
    kdump_cfg_path = vm.params.get(
        "kdump_cfg_path", "/etc/kdump.conf" if os_type == "rhel" else "/etc/default/kdump-tools")
    auth_key_path = vm.params.get("auth_key_path")
    restore_kdumpcf_cmd = "/bin/cp -f %s-bk %s" % (
        kdump_cfg_path, kdump_cfg_path)
    restore_kdumpcf_cmd = vm.params.get(
        "restore_kdumpcf_cmd", restore_kdumpcf_cmd)

    session = vm.wait_for_login(timeout=timeout)
    if auth_key_path:
        restore_key_cmd = "/bin/cp -f %s-bk %s" % (
            auth_key_path, auth_key_path)
        test.log.info("Restore authorized_keys file.")
        process.run(restore_key_cmd, shell=True)

    test.log.info("Restore kdump.conf")
    status, output = session.cmd_status_output(restore_kdumpcf_cmd)
    if status != 0:
        test.log.error(output)
        test.error("Fail to restore the kdump.conf")

    session.close()


@error_context.context_aware
def kdump_enable(
    env, test, params, vm, vm_name, crash_kernel_probe_cmd, kernel_param_cmd, kdump_enable_cmd, timeout
):
    """
    Check, configure and enable the kdump in guest.

    :param vm_name: vm name
    :param crash_kernel_probe_cmd: check if kdump loaded
    :param kernel_param_cmd: the param add into kernel line for kdump
    :param kdump_enable_cmd: enable kdump command
    :param timeout: Timeout in seconds
    """
    os_type = vm.get_distro().lower()
    kdump_cfg_path = vm.params.get(
        "kdump_cfg_path", "/etc/kdump.conf" if os_type == "rhel" else "/etc/default/kdump-tools")
    kdump_config = vm.params.get("kdump_config")
    vmcore_path = vm.params.get("vmcore_path", "/var/crash")
    kdump_method = vm.params.get("kdump_method", "basic")
    kdump_propagate_cmd = vm.params.get("kdump_propagate_cmd", "kdumpctl propagate")
    kdump_enable_timeout = int(vm.params.get("kdump_enable_timeout", 360))

    error_context.context("Try to log into guest '%s'." %
                          vm_name, LOG_JOB.info)
    session = vm.wait_for_login(timeout=timeout)
    error_context.context(
        "Checking the existence of crash kernel in %s" % vm_name, LOG_JOB.info
    )
    try:
        session.cmd(crash_kernel_probe_cmd)
    except Exception:
        error_context.context(
            "Crash kernel is not loaded. Trying to load it", LOG_JOB.info
        )
        error_context.context("Applying kernel parameters...", LOG_JOB.info)
        status, output = session.cmd_status_output(kernel_param_cmd, timeout)
        if status != 0:
            test.log.error("Failed to apply kernel parameters: %s", output)
            test.fail("Kernel parameter command failed")
        if os_type == "ubuntu":
            error_context.context("Updating GRUB configuration...", LOG_JOB.info)
            status, output = session.cmd_status_output("update-grub", timeout)
            if status != 0:
                test.log.error("Failed to update GRUB: %s", output)
                test.fail("update-grub command failed, leaving system in an inconsistent state")
        secure_guest_type = vm.params.get("secure_guest_type")
        if secure_guest_type and secure_guest_type in ['sev_es', 'snp']:
            error_context.context("secure_guest_type: '%s'." %
                                  secure_guest_type, LOG_JOB.info)
            error_context.context("Shutting down the guest", LOG_JOB.info)
            session.close()
            vm.graceful_shutdown(timeout=timeout)
            error_context.context("Done with shutdown", LOG_JOB.info)
            params["start_vm"] = "yes"
            error_context.context("start vm", LOG_JOB.info)
            env_process.preprocess_vm(test, vm.params.copy(), env, vm_name)
            error_context.context(
                "start vm: done with preprocess_vm", LOG_JOB.info)
            vm = env.get_vm(vm_name)
            try:
                session = vm.wait_for_login(timeout=timeout)
            except Exception as e:
                test.fail("Failed to login to VM %s after restart: %s" %
                          (vm_name, str(e)))
        else:
            session = vm.reboot(session, timeout=timeout)

    if kdump_config:
        if kdump_method == "ssh":
            host_ip = utils_net.get_ip_address_by_interface(
                vm.params.get("netdst"))
            kdump_config = kdump_config % (host_ip, vmcore_path)

        error_context.context(
            "Configuring the Core Collector...", LOG_JOB.info)
        if os_type == "rhel":
            session.cmd("cat /dev/null > %s" % kdump_cfg_path)
            session.cmd(
                "echo 'core_collector makedumpfile -F -c -d 31' > %s" % kdump_cfg_path
            )
            for config_line in kdump_config.split(";"):
                config_cmd = "echo -e '%s' >> %s "
                config_con = config_line.strip()
                session.cmd(config_cmd % (config_con, kdump_cfg_path))
        elif os_type == "ubuntu":
            session.cmd("sed -i '/^USE_KDUMP=/d' %s" % kdump_cfg_path)
            session.cmd("echo 'USE_KDUMP=1' >> %s;sync" % kdump_cfg_path)

    if kdump_method == "ssh":
        host_pwd = vm.params.get("host_pwd", "redhat")
        guest_pwd = vm.params.get("guest_pwd", "redhat")
        guest_ip = vm.get_address()

        error_context.context(
            "Setup ssh login without password...", LOG_JOB.info)
        session.cmd("rm -rf /root/.ssh/*")

        ssh_connection = utils_conn.SSHConnection(
            server_ip=host_ip,
            server_pwd=host_pwd,
            client_ip=guest_ip,
            client_pwd=guest_pwd,
        )
        try:
            ssh_connection.conn_check()
        except utils_conn.ConnectionError:
            ssh_connection.conn_setup()
            ssh_connection.conn_check()

        LOG_JOB.info("Trying to propagate with command '%s'",
                     kdump_propagate_cmd)
        session.cmd(kdump_propagate_cmd, timeout=120)

    error_context.context("Enabling kdump service...", LOG_JOB.info)
    # the initrd may be rebuilt here so we need to wait a little more
    session.cmd(kdump_enable_cmd, timeout=kdump_enable_timeout)
    return session


@error_context.context_aware
def crash_test(test, params, env, vm, vcpu, crash_cmd, timeout):
    """
    Trigger a crash dump through sysrq-trigger

    :param vcpu: vcpu which is used to trigger a crash
    :param crash_cmd: crash_cmd which is triggered crash command
    :param timeout: Timeout in seconds
    """
    os_type = vm.get_distro().lower()
    vm_name = vm.name
    secure_guest_type = vm.params.get("secure_guest_type")
    vmcore_path = vm.params.get("vmcore_path", "/var/crash")
    kdump_method = vm.params.get("kdump_method", "basic")
    vmcore_rm_cmd = vm.params.get("vmcore_rm_cmd", "rm -rf %s/*")
    vmcore_rm_cmd = vmcore_rm_cmd % vmcore_path
    kdump_restart_cmd = vm.params.get(
        "kdump_restart_cmd", "systemctl restart kdump.service" if os_type == "rhel" else "systemctl restart kdump-tools.service"
    )
    kdump_status_cmd = vm.params.get(
        "kdump_status_cmd", "systemctl status kdump.service" if os_type == "rhel" else "systemctl status kdump-tools.service"
    )

    kdump_propagate_cmd = vm.params.get("kdump_propagate_cmd", "kdumpctl propagate")

    session = vm.wait_for_login(timeout=timeout)
    test.log.info("Delete the vmcore file.")
    if kdump_method == "ssh":
        output = session.cmd("cat %s" % vm.params["kdump_rsa_path"])
        process.run(vmcore_rm_cmd, shell=True)
        process.run(
            "cat /dev/null > %s" % vm.params["auth_key_path"], shell=True, sudo=True
        )
        authorized_key_cmd = vm.params["authorized_key_cmd"]
        process.run(authorized_key_cmd % output, shell=True, sudo=True)
        session.cmd(kdump_propagate_cmd, timeout=120)
    else:
        session.cmd_output(vmcore_rm_cmd)

    session.cmd(kdump_restart_cmd, timeout=120)

    debug_msg = "Kdump service status before our testing:\n"
    debug_msg += session.cmd(kdump_status_cmd)

    test.log.debug(debug_msg)
    if "failed to load kdump kernel" in debug_msg:
        test.cancel("Test cancelled due to kdump kernel load failure")
    try:
        if crash_cmd == "nmi":
            test.log.info("Triggering crash with 'nmi' interrupt")
            send_nmi_cmd = vm.params.get("send_nmi_cmd")
            session.cmd(send_nmi_cmd)
            vm.monitor.nmi()
        else:
            test.log.info("Triggering crash on vcpu %d ...", vcpu)
            session.sendline("taskset -c %d %s" % (vcpu, crash_cmd))
            if secure_guest_type and secure_guest_type in ['sev_es', 'snp']:
                test.log.info("secure_guest_type: %s", secure_guest_type)
                reboot_pattern = vm.params.get("reboot_pattern")
                start_time = time.time()
                is_shutdown = False
                while (time.time() - start_time) < timeout:
                    output = vm.serial_console.get_output()
                    if re.search(reboot_pattern, output, re.I):
                        test.log.info("VM %s shut down after kdump", vm_name)
                        is_shutdown = True
                        break
                    else:
                        time.sleep(5)
                if not is_shutdown:
                    test.fail("%s VM %s shutdown timedout" %
                              (secure_guest_type, vm_name))
                test.log.info(
                    "VM %s shut down after kdump, starting it back...", vm_name)
                params["start_vm"] = "yes"
                env_process.preprocess_vm(test, vm.params.copy(), env, vm_name)
                vm = env.get_vm(vm_name)
                try:
                    session = vm.wait_for_login(timeout=timeout)
                except Exception as e:
                    test.fail("Failed to login to VM %s after restart: %s" %
                              (vm_name, str(e)))
    except Exception:
        postprocess_kdump(test, vm, timeout)


@error_context.context_aware
def check_vmcore(test, vm, session, timeout):
    """
    Check the vmcore file after triggering a crash

    :param session: A shell session object or None.
    :param timeout: Timeout in seconds
    """
    vmcore_path = vm.params.get("vmcore_path", "/var/crash")
    vmcore_chk_cmd = vm.params.get("vmcore_chk_cmd", "ls -R %s | grep vmcore")
    vmcore_chk_cmd = vmcore_chk_cmd % vmcore_path

    if not utils_misc.wait_for(lambda: not session.is_responsive(), 240, 0, 1):
        test.fail("Could not trigger crash.")

    error_context.context(
        "Waiting for kernel crash dump to complete", test.log.info)
    if vm.params.get("kdump_method") != "ssh":
        session = vm.wait_for_login(timeout=timeout)

    error_context.context("Probing vmcore file...", test.log.info)
    if vm.params.get("kdump_method") == "ssh":
        test.log.info("Checking vmcore file on host")
        status = utils_misc.wait_for(
            lambda: process.system(vmcore_chk_cmd, shell=True) == 0,
            ignore_errors=True,
            timeout=200,
        )
    else:
        test.log.info("Checking vmcore file on guest")
        status = utils_misc.wait_for(
            lambda: session.cmd_status(vmcore_chk_cmd) == 0,
            ignore_errors=True,
            timeout=200,
        )
    if not status:
        postprocess_kdump(test, vm, timeout)
        test.fail("Could not found vmcore file.")

    test.log.info("Found vmcore.")


@error_context.context_aware
def run(test, params, env):
    """
    KVM kdump test:
    1) Log into the guest(s)
    2) Check, configure and enable the kdump
    3) Trigger a crash by 'sysrq-trigger' and check the vmcore for each vcpu,
       or only trigger one crash with 'nmi' interrupt and check vmcore.

    :param test: kvm test object
    :param params: Dictionary with the test parameters
    :param env: Dictionary with test environment.
    """

    timeout = float(params.get("login_timeout", 240))
    crash_timeout = float(params.get("crash_timeout", 360))
    kernel_param_cmd = params.get("kernel_param_cmd")
    os_type = params.get("os_type", env.get_vm(
        params.get("vms").split()[0]).get_distro().lower())
    def_kdump_enable_cmd = "systemctl enable --now kdump.service" if os_type == "rhel" else "systemctl enable --now kdump-tools.service"
    kdump_enable_cmd = params.get("kdump_enable_cmd", def_kdump_enable_cmd)
    def_crash_kernel_probe_cmd = "grep -q 1 /sys/kernel/kexec_crash_loaded"
    crash_kernel_probe_cmd = params.get(
        "crash_kernel_probe_cmd", def_crash_kernel_probe_cmd
    )
    kdump_cfg_path = params.get(
        "kdump_cfg_path", "/etc/kdump.conf" if os_type == "rhel" else "/etc/default/kdump-tools")

    vms = params.get("vms", "vm1 vm2").split()
    vm_list = []
    session_list = []

    try:
        for vm_name in vms:
            vm = env.get_vm(vm_name)
            secure_guest_type = vm.params.get("vm_secure_guest_type")
            vm.verify_alive()
            if secure_guest_type and secure_guest_type in [
                    'sev', 'sev_es', 'snp']:
                session = vm.wait_for_login(timeout=timeout)
                utils_misc.verify_sev(session, params, vm)
                session.close()
            vm_list.append(vm)

            preprocess_kdump(test, vm, timeout)
            vm.copy_files_from(
                kdump_cfg_path, os.path.join(
                    test.debugdir, "kdump.conf-%s" % vm_name)
            )

            session = kdump_enable(
                env,
                test,
                params,
                vm,
                vm_name,
                crash_kernel_probe_cmd,
                kernel_param_cmd,
                kdump_enable_cmd,
                timeout,
            )

            session_list.append(session)

        for vm in vm_list:
            error_context.context(
                "Kdump Testing, force the Linux kernel to crash", test.log.info
            )
            crash_cmd = params.get("crash_cmd", "echo c > /proc/sysrq-trigger")

            session = vm.wait_for_login(timeout=timeout)
            vm.copy_files_from(
                kdump_cfg_path,
                os.path.join(test.debugdir, "kdump.conf-%s-test" % vm.name),
            )
            if crash_cmd == "nmi":
                crash_test(test, params, env, vm, None, crash_cmd, timeout)
            else:
                # trigger crash for each vcpu
                nvcpu = int(params.get("smp", 1))
                for i in range(nvcpu):
                    crash_test(test, params, env, vm, i, crash_cmd, timeout)
            session.close()

        for i in range(len(vm_list)):
            error_context.context(
                "Check the vmcore file after triggering a crash", test.log.info
            )
            check_vmcore(test, vm_list[i], session_list[i], crash_timeout)
    finally:
        for s in session_list:
            s.close()
        for vm in vm_list:
            postprocess_kdump(test, vm, timeout)
            vm.destroy()
