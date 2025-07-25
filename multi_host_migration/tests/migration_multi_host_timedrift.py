import logging
import re
import time

from autotest.client.shared import error, utils
from autotest.client.shared.syncdata import SyncData
from virttest import utils_test
from virttest.utils_test.qemu import migration


@error.context_aware
def run(test, params, env):
    """
    KVM multi-host migration test:

    Migration execution progress is described in documentation
    for migrate method in class MultihostMigration.

    :param test: kvm test object.
    :param params: Dictionary with test parameters.
    :param env: Dictionary with the test environment.
    """
    mig_protocol = params.get("mig_protocol", "tcp")
    base_class = migration.MultihostMigration
    if mig_protocol == "fd":
        base_class = migration.MultihostMigrationFd
    if mig_protocol == "exec":
        base_class = migration.MultihostMigrationExec
    if "rdma" in mig_protocol:
        base_class = migration.MultihostMigrationRdma

    class TestMultihostMigration(base_class):
        def __init__(self, test, params, env):
            super(TestMultihostMigration, self).__init__(test, params, env)
            self.srchost = self.params.get("hosts")[0]
            self.dsthost = self.params.get("hosts")[1]
            self.is_src = params["hostid"] == self.srchost
            self.vms = params["vms"].split()
            self.migrate_count = int(params.get("migrate_count", "1"))
            self.migration_timeout = int(params.get("migrate_timeout", "240"))

            self.time_command = params["time_command"]
            self.time_filter_re = params["time_filter_re"]
            self.time_format = params["time_format"]
            self.create_file = params["create_file"]

            self.diff_limit = float(params.get("time_diff_limit", "0.1"))
            self.start_ht = {}
            self.start_gt = {}
            self.diff_ht = {}
            self.diff_gt = {}
            self.id = {"src": self.srchost, "dst": self.dsthost, "type": "timedrift"}

            self.sync = SyncData(
                self.master_id(), self.hostid, self.hosts, self.id, self.sync_server
            )

        @error.context_aware
        def check_diff(self, mig_data):
            logging.debug("Sleep 10s")
            time.sleep(10)
            time_drifted = False
            for vm in mig_data.vms:
                session = vm.wait_for_login()

                if self.is_src:
                    error.context("Check the clocksource in guest.", logging.info)
                    check_clocksource_cmd = params.get("check_clocksource_cmd")
                    clocksource = params.get("clocksource", "kvm-clock")
                    current_clocksource = session.cmd(check_clocksource_cmd)
                    current_clocksource = re.findall(clocksource, current_clocksource)
                    current_clocksource = "".join(current_clocksource)
                    logging.info(
                        "current_clocksource in guest is: '%s'", current_clocksource
                    )
                    if clocksource == "kvm-clock":
                        s = current_clocksource == "kvm-clock"
                    else:
                        s = current_clocksource != "kvm-clock"
                    if not s:
                        raise error.TestFail(
                            "Guest didn't use '%s' clocksource" % clocksource
                        )

                error.context("Check the system time on guest and host.", logging.info)
                (ht, gt) = utils_test.get_time(
                    session, self.time_command, self.time_filter_re, self.time_format
                )
                session.cmd(self.create_file)
                if vm.name not in self.start_ht.keys():
                    (self.start_ht[vm.name], self.start_gt[vm.name]) = (ht, gt)
                    if abs(ht - gt) > self.diff_limit:
                        logging.warning(
                            "Host and %s time diff %s is greater "
                            "than time_diff_limit:%s",
                            vm.name,
                            abs(ht - gt),
                            self.diff_limit,
                        )
                        logging.warning(
                            "Host time:%s   Guest %s time:%s", ht, vm.name, gt
                        )
                else:
                    self.diff_ht[vm.name] = ht - self.start_ht[vm.name]
                    self.diff_gt[vm.name] = gt - self.start_gt[vm.name]

                    gh_diff = self.diff_ht[vm.name] - self.diff_gt[vm.name]
                    if gh_diff > self.diff_limit:
                        time_drifted = True
            if time_drifted:
                difs = ""
                for vm in mig_data.vms:
                    difs += "\n            VM=%s  HOST=%ss  GUEST=%ss DIFF=%s" % (
                        vm.name,
                        self.diff_ht[vm.name],
                        self.diff_gt[vm.name],
                        (self.diff_ht[vm.name] - self.diff_gt[vm.name]),
                    )
                raise error.TestError(
                    "Time DIFFERENCE for VM is greater than"
                    " LIMIT:%ss.%s\n" % (self.diff_limit, difs)
                )

        def before_migration(self, mig_data):
            """
            Sync time values
            """
            data = self.sync.sync((self.start_ht, self.start_gt), timeout=120)
            (self.start_ht, self.start_gt) = data[self.srchost]

        def ping_pong_migrate(self):
            for _ in range(self.migrate_count):
                self.sync.sync(True, timeout=self.migration_timeout)
                self.migrate_wait(
                    self.vms,
                    self.srchost,
                    self.dsthost,
                    start_work=self.check_diff,
                    check_work=self.check_diff,
                )
                tmp = self.dsthost
                self.dsthost = self.srchost
                self.srchost = tmp

        def migration_scenario(self, worker=None):
            error.context(
                "Migration from %s to %s over protocol %s."
                % (self.srchost, self.dsthost, mig_protocol),
                logging.info,
            )

            self.ping_pong_migrate()

    error.context("Sync host time with ntp server.", logging.info)
    sync_cmd = params.get("host_sync_time_cmd", "ntpdate -b pool.ntp.org")
    utils.run(sync_cmd, 20)

    mig = TestMultihostMigration(test, params, env)
    mig.run()
