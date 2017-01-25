# Copyright 2015 Deutsche Telekom AG
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ddt

from oslo_log import log as logging
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
import testtools
from testtools import testcase as tc

from manila_tempest_tests.common import constants
from manila_tempest_tests.tests.api import base
from manila_tempest_tests.tests.scenario import manager_share as manager
from manila_tempest_tests import utils

CONF = config.CONF

LOG = logging.getLogger(__name__)


@ddt.ddt
class ShareBasicOpsBase(manager.ShareScenarioTest):

    """This smoke test case follows this basic set of operations:

     * Create share network
     * Create share
     * Launch an instance
     * Allow access
     * Perform ssh to instance
     * Mount share
     * Terminate the instance
    """
    protocol = None

    def setUp(self):
        super(ShareBasicOpsBase, self).setUp()
        base.verify_test_has_appropriate_tags(self)
        self.image_ref = None
        # Setup image and flavor the test instance
        # Support both configured and injected values
        self.floatings = {}
        if self.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % self.protocol
            raise self.skipException(message)
        if self.protocol not in CONF.share.enable_ip_rules_for_protocols:
            message = ("%s tests for access rules other than IP are disabled" %
                       self.protocol)
            raise self.skipException(message)
        if not hasattr(self, 'flavor_ref'):
            self.flavor_ref = CONF.share.client_vm_flavor_ref
        if CONF.share.image_with_share_tools:
            images = self.compute_images_client.list_images()["images"]
            for img in images:
                if img["name"] == CONF.share.image_with_share_tools:
                    self.image_ref = img['id']
                    break
            if not self.image_ref:
                msg = ("Image %s not found" %
                       CONF.share.image_with_share_tools)
                raise exceptions.InvalidConfiguration(message=msg)
        self.ssh_user = CONF.share.image_username
        LOG.debug('Starting test for i:{image}, f:{flavor}. '
                  'user: {ssh_user}'.format(
                      image=self.image_ref, flavor=self.flavor_ref,
                      ssh_user=self.ssh_user))
        self.security_group = self._create_security_group()
        self.create_share_network()

    def boot_instance(self, wait_until="ACTIVE"):
        self.keypair = self.create_keypair()
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'key_name': self.keypair['name'],
            'security_groups': security_groups,
            'wait_until': wait_until,
        }
        if CONF.share.multitenancy_enabled:
            create_kwargs['networks'] = [{'uuid': self.net['id']}, ]
        instance = self.create_server(
            image_id=self.image_ref, flavor=self.flavor_ref, **create_kwargs)
        return instance

    def init_ssh(self, instance, do_ping=False):
        # Obtain a floating IP
        floating_ip = (self.compute_floating_ips_client.create_floating_ip()
                       ['floating_ip'])
        self.floatings[instance['id']] = floating_ip
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.compute_floating_ips_client.delete_floating_ip,
                        floating_ip['id'])
        # Attach a floating IP
        self.compute_floating_ips_client.associate_floating_ip_to_server(
            floating_ip['ip'], instance['id'])
        # Check ssh
        ssh_client = self.get_remote_client(
            server_or_ip=floating_ip['ip'],
            username=self.ssh_user,
            private_key=self.keypair['private_key'])

        # NOTE(u_glide): Workaround for bug #1465682
        ssh_client = ssh_client.ssh_client

        self.share = self.shares_client.get_share(self.share['id'])
        if do_ping:
            server_ip = self.share['export_location'].split(":")[0]
            ssh_client.exec_command("ping -c 1 %s" % server_ip)
        return ssh_client

    def mount_share(self, location, ssh_client, target_dir=None):
        raise NotImplementedError

    def umount_share(self, ssh_client, target_dir=None):
        target_dir = target_dir or "/mnt"
        ssh_client.exec_command("sudo umount %s" % target_dir)

    def write_data(self, data, ssh_client):
        ssh_client.exec_command("echo \"%s\" | sudo tee /mnt/t1 && sudo sync" %
                                data)

    def read_data(self, ssh_client):
        data = ssh_client.exec_command("sudo cat /mnt/t1")
        return data.rstrip()

    def migrate_share(self, share_id, dest_host, status, force_host_assisted):
        share = self._migrate_share(
            share_id, dest_host, status, force_host_assisted,
            self.shares_admin_v2_client)
        return share

    def migration_complete(self, share_id, dest_host):
        return self._migration_complete(share_id, dest_host)

    def create_share_network(self):
        self.net = self._create_network(namestart="manila-share")
        self.subnet = self._create_subnet(network=self.net,
                                          namestart="manila-share-sub")
        router = self._get_router()
        self._create_router_interface(subnet_id=self.subnet['id'],
                                      router_id=router['id'])
        self.share_net = self._create_share_network(
            neutron_net_id=self.net['id'],
            neutron_subnet_id=self.subnet['id'],
            name=data_utils.rand_name("sn-name"))

    def _get_share_type(self):
        if CONF.share.default_share_type_name:
            return self.shares_client.get_share_type(
                CONF.share.default_share_type_name)['share_type']
        return self._create_share_type(
            data_utils.rand_name("share_type"),
            extra_specs={
                'snapshot_support': CONF.share.capability_snapshot_support,
                'driver_handles_share_servers': CONF.share.multitenancy_enabled
            },)['share_type']

    def create_share(self, **kwargs):
        kwargs.update({
            'share_protocol': self.protocol,
        })
        if not ('share_type_id' in kwargs or 'snapshot_id' in kwargs):
            kwargs.update({'share_type_id': self._get_share_type()['id']})
        if CONF.share.multitenancy_enabled:
            kwargs.update({'share_network_id': self.share_net['id']})
        self.share = self._create_share(**kwargs)
        return self.share

    def allow_access_ip(self, share_id, ip=None, instance=None, cleanup=True,
                        snapshot=None):
        if instance and not ip:
            try:
                net_addresses = instance['addresses']
                first_address = net_addresses.values()[0][0]
                ip = first_address['addr']
            except Exception:
                LOG.debug("Instance: %s" % instance)
                # In case on an error ip will be still none
                LOG.exception("Instance does not have a valid IP address."
                              "Falling back to default")
        if not ip:
            ip = '0.0.0.0/0'

        if snapshot:
            self._allow_access_snapshot(snapshot['id'], access_type='ip',
                                        access_to=ip, cleanup=cleanup)
        else:
            self._allow_access(share_id, access_type='ip', access_to=ip,
                               cleanup=cleanup)

    def provide_access_to_auxiliary_instance(self, instance, share=None,
                                             snapshot=None):
        share = share or self.share
        if self.protocol.lower() == 'cifs':
            self.allow_access_ip(
                share['id'], instance=instance, cleanup=False,
                snapshot=snapshot)
        elif not CONF.share.multitenancy_enabled:
            self.allow_access_ip(
                share['id'], ip=self.floatings[instance['id']]['ip'],
                instance=instance, cleanup=False, snapshot=snapshot)
        elif (CONF.share.multitenancy_enabled and
              self.protocol.lower() == 'nfs'):
            self.allow_access_ip(
                share['id'], instance=instance, cleanup=False,
                snapshot=snapshot)

    def wait_for_active_instance(self, instance_id):
        waiters.wait_for_server_status(
            self.manager.servers_client, instance_id, "ACTIVE")
        return self.manager.servers_client.show_server(instance_id)["server"]

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    def test_mount_share_one_vm(self):
        instance = self.boot_instance(wait_until="BUILD")
        self.create_share()
        instance = self.wait_for_active_instance(instance["id"])
        ssh_client = self.init_ssh(instance)

        self.provide_access_to_auxiliary_instance(instance)

        if utils.is_microversion_lt(CONF.share.max_api_microversion, "2.9"):
            locations = self.share['export_locations']
        else:
            exports = self.shares_v2_client.list_share_export_locations(
                self.share['id'])
            locations = [x['path'] for x in exports]

        for location in locations:
            self.mount_share(location, ssh_client)
            self.umount_share(ssh_client)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    def test_read_write_two_vms(self):
        """Boots two vms and writes/reads data on it."""
        test_data = "Some test data to write"

        # Boot two VMs and create share
        instance1 = self.boot_instance(wait_until="BUILD")
        instance2 = self.boot_instance(wait_until="BUILD")
        self.create_share()
        instance1 = self.wait_for_active_instance(instance1["id"])
        instance2 = self.wait_for_active_instance(instance2["id"])

        # Write data to first VM
        ssh_client_inst1 = self.init_ssh(instance1)
        self.provide_access_to_auxiliary_instance(instance1)

        if utils.is_microversion_lt(CONF.share.max_api_microversion, "2.9"):
            locations = self.share['export_locations']
        else:
            exports = self.shares_v2_client.list_share_export_locations(
                self.share['id'])
            locations = [x['path'] for x in exports]

        self.mount_share(locations[0], ssh_client_inst1)
        self.addCleanup(self.umount_share,
                        ssh_client_inst1)
        self.write_data(test_data, ssh_client_inst1)

        # Read from second VM
        ssh_client_inst2 = self.init_ssh(instance2)
        self.provide_access_to_auxiliary_instance(instance2)
        self.mount_share(locations[0], ssh_client_inst2)
        self.addCleanup(self.umount_share,
                        ssh_client_inst2)
        data = self.read_data(ssh_client_inst2)
        self.assertEqual(test_data, data)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.29")
    @testtools.skipUnless(CONF.share.run_host_assisted_migration_tests or
                          CONF.share.run_driver_assisted_migration_tests,
                          "Share migration tests are disabled.")
    @ddt.data(True, False)
    def test_migration_files(self, force_host_assisted):

        if (force_host_assisted and
                not CONF.share.run_host_assisted_migration_tests):
                raise self.skipException("Host-assisted migration tests are "
                                         "disabled.")
        elif (not force_host_assisted and
              not CONF.share.run_driver_assisted_migration_tests):
            raise self.skipException("Driver-assisted migration tests are "
                                     "disabled.")

        if self.protocol != "nfs":
            raise self.skipException("Only NFS protocol supported "
                                     "at this moment.")

        pools = self.shares_admin_v2_client.list_pools(detail=True)['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries are "
                                     "needed to run share migration tests.")

        instance = self.boot_instance(wait_until="BUILD")
        self.create_share()
        instance = self.wait_for_active_instance(instance["id"])
        self.share = self.shares_client.get_share(self.share['id'])

        default_type = self.shares_v2_client.list_share_types(
            default=True)['share_type']

        dest_pool = utils.choose_matching_backend(
            self.share, pools, default_type)

        self.assertIsNotNone(dest_pool)
        self.assertIsNotNone(dest_pool.get('name'))

        dest_pool = dest_pool['name']

        ssh_client = self.init_ssh(instance)
        self.provide_access_to_auxiliary_instance(instance)

        exports = self.shares_v2_client.list_share_export_locations(
            self.share['id'])
        self.assertNotEmpty(exports)
        exports = [x['path'] for x in exports]
        self.assertNotEmpty(exports)

        self.mount_share(exports[0], ssh_client)

        ssh_client.exec_command("sudo mkdir -p /mnt/f1")
        ssh_client.exec_command("sudo mkdir -p /mnt/f2")
        ssh_client.exec_command("sudo mkdir -p /mnt/f3")
        ssh_client.exec_command("sudo mkdir -p /mnt/f4")
        ssh_client.exec_command("sudo mkdir -p /mnt/f1/ff1")
        ssh_client.exec_command("sleep 1")
        ssh_client.exec_command(
            "sudo dd if=/dev/zero of=/mnt/f1/1m1.bin bs=1M count=1")
        ssh_client.exec_command(
            "sudo dd if=/dev/zero of=/mnt/f2/1m2.bin bs=1M count=1")
        ssh_client.exec_command(
            "sudo dd if=/dev/zero of=/mnt/f3/1m3.bin bs=1M count=1")
        ssh_client.exec_command(
            "sudo dd if=/dev/zero of=/mnt/f4/1m4.bin bs=1M count=1")
        ssh_client.exec_command(
            "sudo dd if=/dev/zero of=/mnt/f1/ff1/1m5.bin bs=1M count=1")
        ssh_client.exec_command("sudo chmod -R 555 /mnt/f3")
        ssh_client.exec_command("sudo chmod -R 777 /mnt/f4")

        task_state = (constants.TASK_STATE_DATA_COPYING_COMPLETED
                      if force_host_assisted
                      else constants.TASK_STATE_MIGRATION_DRIVER_PHASE1_DONE)

        self.share = self.migrate_share(
            self.share['id'], dest_pool, task_state, force_host_assisted)

        read_only = False
        if force_host_assisted:
            try:
                ssh_client.exec_command(
                    "dd if=/dev/zero of=/mnt/f1/1m6.bin bs=1M count=1")
            except Exception:
                read_only = True
            self.assertTrue(read_only)

        self.umount_share(ssh_client)

        self.share = self.migration_complete(self.share['id'], dest_pool)

        new_exports = self.shares_v2_client.list_share_export_locations(
            self.share['id'])
        self.assertNotEmpty(new_exports)
        new_exports = [x['path'] for x in new_exports]
        self.assertNotEmpty(new_exports)

        self.assertEqual(dest_pool, self.share['host'])
        self.assertEqual(constants.TASK_STATE_MIGRATION_SUCCESS,
                         self.share['task_state'])

        self.mount_share(new_exports[0], ssh_client)

        output = ssh_client.exec_command("ls -lRA --ignore=lost+found /mnt")

        self.umount_share(ssh_client)

        self.assertIn('1m1.bin', output)
        self.assertIn('1m2.bin', output)
        self.assertIn('1m3.bin', output)
        self.assertIn('1m4.bin', output)
        self.assertIn('1m5.bin', output)

    def _get_user_export_location(self, share=None, snapshot=None):
        user_export_location = None
        if share:
            if utils.is_microversion_lt(
                    CONF.share.max_api_microversion, "2.9"):
                user_export_location = share['export_locations'][0]
            else:
                exports = self.shares_v2_client.list_share_export_locations(
                    share['id'])
                locations = [x['path'] for x in exports]
                user_export_location = locations[0]
        elif snapshot:
            exports = (self.shares_v2_client.
                       list_snapshot_export_locations(snapshot['id']))
            locations = [x['path'] for x in exports]
            user_export_location = locations[0]
        self.assertIsNotNone(user_export_location)
        return user_export_location

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @testtools.skipUnless(
        CONF.share.run_snapshot_tests, "Snapshot tests are disabled.")
    def test_write_data_to_share_created_from_snapshot(self):
        if self.protocol.upper() == 'CIFS':
            msg = "Skipped for CIFS protocol because of bug/1649573"
            raise self.skipException(msg)

        # 1 - Create UVM, ok, created
        instance = self.boot_instance(wait_until="BUILD")

        # 2 - Create share S1, ok, created
        parent_share = self.create_share()
        instance = self.wait_for_active_instance(instance["id"])
        self.addCleanup(self.servers_client.delete_server, instance['id'])

        # 3 - SSH to UVM, ok, connected
        ssh_client = self.init_ssh(instance)

        # 4 - Provide RW access to S1, ok, provided
        self.provide_access_to_auxiliary_instance(instance, parent_share)

        # 5 - Try mount S1 to UVM, ok, mounted
        user_export_location = self._get_user_export_location(parent_share)
        parent_share_dir = "/mnt/parent"
        ssh_client.exec_command("sudo mkdir -p %s" % parent_share_dir)
        self.mount_share(user_export_location, ssh_client, parent_share_dir)
        self.addCleanup(self.umount_share, ssh_client, parent_share_dir)

        # 6 - Create "file1", ok, created
        ssh_client.exec_command("sudo touch %s/file1" % parent_share_dir)

        # 7 - Create snapshot SS1 from S1, ok, created
        snapshot = self._create_snapshot(parent_share['id'])

        # 8 - Create "file2" in share S1 - ok, created. We expect that
        # snapshot will not contain any data created after snapshot creation.
        ssh_client.exec_command("sudo touch %s/file2" % parent_share_dir)

        # 9 - Create share S2 from SS1, ok, created
        child_share = self.create_share(snapshot_id=snapshot["id"])

        # 10 - Try mount S2 - fail, access denied. We test that child share
        #      did not get access rules from parent share.
        user_export_location = self._get_user_export_location(child_share)
        child_share_dir = "/mnt/child"
        ssh_client.exec_command("sudo mkdir -p %s" % child_share_dir)
        self.assertRaises(
            exceptions.SSHExecCommandFailed,
            self.mount_share,
            user_export_location, ssh_client, child_share_dir,
        )

        # 11 - Provide RW access to S2, ok, provided
        self.provide_access_to_auxiliary_instance(instance, child_share)

        # 12 - Try mount S2, ok, mounted
        self.mount_share(user_export_location, ssh_client, child_share_dir)
        self.addCleanup(self.umount_share, ssh_client, child_share_dir)

        # 13 - List files on S2, only "file1" exists
        output = ssh_client.exec_command("sudo ls -lRA %s" % child_share_dir)
        self.assertIn('file1', output)
        self.assertNotIn('file2', output)

        # 14 - Create file3 on S2, ok, file created
        ssh_client.exec_command("sudo touch %s/file3" % child_share_dir)

        # 15 - List files on S1, two files exist - "file1" and "file2"
        output = ssh_client.exec_command("sudo ls -lRA %s" % parent_share_dir)
        self.assertIn('file1', output)
        self.assertIn('file2', output)
        self.assertNotIn('file3', output)

        # 16 - List files on S2, two files exist - "file1" and "file3"
        output = ssh_client.exec_command("sudo ls -lRA %s" % child_share_dir)
        self.assertIn('file1', output)
        self.assertNotIn('file2', output)
        self.assertIn('file3', output)

    @tc.attr(base.TAG_POSITIVE, base.TAG_BACKEND)
    @base.skip_if_microversion_lt("2.32")
    @testtools.skipUnless(CONF.share.run_mount_snapshot_tests,
                          'Mountable snapshots tests are disabled.')
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_read_mountable_snapshot(self):
        if self.protocol.upper() == 'CIFS':
            msg = "Skipped for CIFS protocol because of bug/1649573"
            raise self.skipException(msg)

        # 1 - Create UVM, ok, created
        instance = self.boot_instance(wait_until="BUILD")

        # 2 - Create share S1, ok, created
        parent_share = self.create_share()
        instance = self.wait_for_active_instance(instance["id"])
        self.addCleanup(self.servers_client.delete_server, instance['id'])

        # 3 - SSH to UVM, ok, connected
        ssh_client = self.init_ssh(instance)

        # 4 - Provide RW access to S1, ok, provided
        self.provide_access_to_auxiliary_instance(instance, parent_share)

        # 5 - Try mount S1 to UVM, ok, mounted
        user_export_location = self._get_user_export_location(parent_share)
        parent_share_dir = "/mnt/parent"
        snapshot_dir = "/mnt/snapshot_dir"
        ssh_client.exec_command("sudo mkdir -p %s" % parent_share_dir)
        ssh_client.exec_command("sudo mkdir -p %s" % snapshot_dir)
        self.mount_share(user_export_location, ssh_client, parent_share_dir)
        self.addCleanup(self.umount_share, ssh_client, parent_share_dir)

        # 6 - Create "file1", ok, created
        ssh_client.exec_command("sudo touch %s/file1" % parent_share_dir)

        # 7 - Create snapshot SS1 from S1, ok, created
        snapshot = self._create_snapshot(parent_share['id'])

        # 8 - Create "file2" in share S1 - ok, created. We expect that
        # snapshot will not contain any data created after snapshot creation.
        ssh_client.exec_command("sudo touch %s/file2" % parent_share_dir)

        # 9 - Allow access to SS1
        self.provide_access_to_auxiliary_instance(instance, snapshot=snapshot)

        # 10 - Mount SS1
        user_export_location = self._get_user_export_location(
            snapshot=snapshot)
        self.mount_share(user_export_location, ssh_client, snapshot_dir)
        self.addCleanup(self.umount_share, ssh_client, snapshot_dir)

        # 11 - List files on SS1, only "file1" exists
        # NOTE(lseki): using ls without recursion to avoid permission denied
        #              error while listing lost+found directory on LVM volumes
        output = ssh_client.exec_command("sudo ls -lA %s" % snapshot_dir)
        self.assertIn('file1', output)
        self.assertNotIn('file2', output)

        # 12 - Try to create a file on SS1, should fail
        self.assertRaises(
            exceptions.SSHExecCommandFailed,
            ssh_client.exec_command,
            "sudo touch %s/file3" % snapshot_dir)


class TestShareBasicOpsNFS(ShareBasicOpsBase):
    protocol = "nfs"

    def mount_share(self, location, ssh_client, target_dir=None):
        target_dir = target_dir or "/mnt"
        ssh_client.exec_command(
            "sudo mount -vt nfs \"%s\" %s" % (location, target_dir))


class TestShareBasicOpsCIFS(ShareBasicOpsBase):
    protocol = "cifs"

    def mount_share(self, location, ssh_client, target_dir=None):
        location = location.replace("\\", "/")
        target_dir = target_dir or "/mnt"
        ssh_client.exec_command(
            "sudo mount.cifs \"%s\" %s -o guest" % (location, target_dir)
        )


# NOTE(u_glide): this function is required to exclude ShareBasicOpsBase from
# executed test cases.
# See: https://docs.python.org/2/library/unittest.html#load-tests-protocol
# for details.
def load_tests(loader, tests, _):
    result = []
    for test_case in tests:
        if type(test_case._tests[0]) is ShareBasicOpsBase:
            continue
        result.append(test_case)
    return loader.suiteClass(result)
