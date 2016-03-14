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

from oslo_log import log as logging
from tempest import config  # noqa
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test  # noqa

from manila_tempest_tests.tests.scenario import manager_share as manager
from manila_tempest_tests import utils

CONF = config.CONF

LOG = logging.getLogger(__name__)


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
        # Setup image and flavor the test instance
        # Support both configured and injected values
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

    def boot_instance(self):
        self.keypair = self.create_keypair()
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'key_name': self.keypair['name'],
            'security_groups': security_groups,
            'wait_until': 'ACTIVE',
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
        self.addCleanup(self.delete_wrapper,
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

    def mount_share(self, location, ssh_client):
        raise NotImplementedError

    def umount_share(self, ssh_client):
        ssh_client.exec_command("sudo umount /mnt")

    def write_data(self, data, ssh_client):
        ssh_client.exec_command("echo \"%s\" | sudo tee /mnt/t1 && sudo sync" %
                                data)

    def read_data(self, ssh_client):
        data = ssh_client.exec_command("sudo cat /mnt/t1")
        return data.rstrip()

    def migrate_share(self, share_id, dest_host):
        share = self._migrate_share(share_id, dest_host,
                                    self.shares_admin_v2_client)
        return share

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
                'driver_handles_share_servers': CONF.share.multitenancy_enabled
            },)['share_type']

    def create_share(self):
        kwargs = {
            'share_protocol': self.protocol,
            'share_type_id': self._get_share_type()['id'],
        }
        if CONF.share.multitenancy_enabled:
            self.create_share_network()
            kwargs.update({'share_network_id': self.share_net['id']})
        self.share = self._create_share(**kwargs)

    def allow_access_ip(self, share_id, ip=None, instance=None, cleanup=True):
        if instance and not ip:
            try:
                net_addresses = instance['addresses']
                first_address = net_addresses.values()[0][0]
                ip = first_address['addr']
            except Exception:
                # In case on an error ip will be still none
                LOG.exception("Instance does not have a valid IP address."
                              "Falling back to default")
        if not ip:
            ip = '0.0.0.0/0'
        self._allow_access(share_id, access_type='ip', access_to=ip,
                           cleanup=cleanup)

    @test.services('compute', 'network')
    def test_mount_share_one_vm(self):
        self.security_group = self._create_security_group()
        self.create_share()
        instance = self.boot_instance()
        self.allow_access_ip(self.share['id'], instance=instance,
                             cleanup=False)
        ssh_client = self.init_ssh(instance)

        if utils.is_microversion_lt(CONF.share.max_api_microversion, "2.9"):
            locations = self.share['export_locations']
        else:
            exports = self.shares_v2_client.list_share_export_locations(
                self.share['id'])
            locations = [x['path'] for x in exports]

        for location in locations:
            self.mount_share(location, ssh_client)
            self.umount_share(ssh_client)
        self.servers_client.delete_server(instance['id'])

    @test.services('compute', 'network')
    def test_read_write_two_vms(self):
        """Boots two vms and writes/reads data on it."""
        test_data = "Some test data to write"
        self.security_group = self._create_security_group()
        self.create_share()

        # boot first VM and write data
        instance1 = self.boot_instance()
        self.allow_access_ip(self.share['id'], instance=instance1,
                             cleanup=False)
        ssh_client_inst1 = self.init_ssh(instance1)

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

        # boot second VM and read
        instance2 = self.boot_instance()
        self.allow_access_ip(self.share['id'], instance=instance2)
        ssh_client_inst2 = self.init_ssh(instance2)
        self.mount_share(locations[0], ssh_client_inst2)
        self.addCleanup(self.umount_share,
                        ssh_client_inst2)
        data = self.read_data(ssh_client_inst2)
        self.assertEqual(test_data, data)

    @test.services('compute', 'network')
    def test_migration_files(self):

        if self.protocol == "CIFS":
            raise self.skipException("Test for CIFS protocol not supported "
                                     "at this moment. Skipping.")

        if not CONF.share.run_migration_tests:
            raise self.skipException("Migration tests disabled. Skipping.")

        pools = self.shares_admin_client.list_pools()['pools']

        if len(pools) < 2:
            raise self.skipException("At least two different pool entries "
                                     "are needed to run migration tests. "
                                     "Skipping.")

        self.security_group = self._create_security_group()
        self.create_share()
        share = self.shares_client.get_share(self.share['id'])

        dest_pool = next((x for x in pools if x['name'] != share['host']),
                         None)

        self.assertIsNotNone(dest_pool)
        self.assertIsNotNone(dest_pool.get('name'))

        dest_pool = dest_pool['name']

        instance1 = self.boot_instance()
        self.allow_access_ip(self.share['id'], instance=instance1,
                             cleanup=False)
        ssh_client = self.init_ssh(instance1)

        if utils.is_microversion_lt(CONF.share.max_api_microversion, "2.9"):
            locations = self.share['export_locations']
        else:
            exports = self.shares_v2_client.list_share_export_locations(
                self.share['id'])
            locations = [x['path'] for x in exports]

        self.mount_share(locations[0], ssh_client)

        ssh_client.exec_command("mkdir -p /mnt/f1")
        ssh_client.exec_command("mkdir -p /mnt/f2")
        ssh_client.exec_command("mkdir -p /mnt/f3")
        ssh_client.exec_command("mkdir -p /mnt/f4")
        ssh_client.exec_command("mkdir -p /mnt/f1/ff1")
        ssh_client.exec_command("sleep 1")
        ssh_client.exec_command("dd if=/dev/zero of=/mnt/f1/1m1.bin bs=1M"
                                " count=1")
        ssh_client.exec_command("dd if=/dev/zero of=/mnt/f2/1m2.bin bs=1M"
                                " count=1")
        ssh_client.exec_command("dd if=/dev/zero of=/mnt/f3/1m3.bin bs=1M"
                                " count=1")
        ssh_client.exec_command("dd if=/dev/zero of=/mnt/f4/1m4.bin bs=1M"
                                " count=1")
        ssh_client.exec_command("dd if=/dev/zero of=/mnt/f1/ff1/1m5.bin bs=1M"
                                " count=1")
        ssh_client.exec_command("chmod -R 555 /mnt/f3")
        ssh_client.exec_command("chmod -R 777 /mnt/f4")

        self.umount_share(ssh_client)

        share = self.migrate_share(share['id'], dest_pool)
        if utils.is_microversion_lt(CONF.share.max_api_microversion, "2.9"):
            new_locations = self.share['export_locations']
        else:
            new_exports = self.shares_v2_client.list_share_export_locations(
                self.share['id'])
            new_locations = [x['path'] for x in new_exports]

        self.assertEqual(dest_pool, share['host'])
        locations.sort()
        new_locations.sort()
        self.assertNotEqual(locations, new_locations)
        self.assertEqual('migration_success', share['task_state'])

        self.mount_share(new_locations[0], ssh_client)

        output = ssh_client.exec_command("ls -lRA --ignore=lost+found /mnt")

        self.umount_share(ssh_client)

        self.assertTrue('1m1.bin' in output)
        self.assertTrue('1m2.bin' in output)
        self.assertTrue('1m3.bin' in output)
        self.assertTrue('1m4.bin' in output)
        self.assertTrue('1m5.bin' in output)


class TestShareBasicOpsNFS(ShareBasicOpsBase):
    protocol = "NFS"

    def mount_share(self, location, ssh_client):
        ssh_client.exec_command("sudo mount -vt nfs \"%s\" /mnt" % location)


class TestShareBasicOpsCIFS(ShareBasicOpsBase):
    protocol = "CIFS"

    def mount_share(self, location, ssh_client):
        location = location.replace("\\", "/")
        ssh_client.exec_command(
            "sudo mount.cifs \"%s\" /mnt -o guest" % location
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
