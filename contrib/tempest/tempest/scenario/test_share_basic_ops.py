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

from oslo_log import log as logging  # noqa
from tempest_lib.common.utils import data_utils  # noqa

from tempest import config
from tempest.scenario import manager_share as manager
from tempest.scenario import utils as test_utils
from tempest import test

CONF = config.CONF

LOG = logging.getLogger(__name__)

load_tests = test_utils.load_tests_input_scenario_utils


class TestShareBasicOps(manager.ShareScenarioTest):

    """This smoke test case follows this basic set of operations:

     * Create share network
     * Create share
     * Launch an instance
     * Allow access
     * Perform ssh to instance
     * Terminate the instance
    """
    protocol = "NFS"

    def setUp(self):
        super(TestShareBasicOps, self).setUp()
        # Setup image and flavor the test instance
        # Support both configured and injected values
        if not hasattr(self, 'image_ref'):
            self.image_ref = CONF.compute.image_ref
        if not hasattr(self, 'flavor_ref'):
            self.flavor_ref = CONF.compute.flavor_ref
        self.image_utils = test_utils.ImageUtils()
        if not self.image_utils.is_flavor_enough(self.flavor_ref,
                                                 self.image_ref):
            raise self.skipException(
                '{image} does not fit in {flavor}'.format(
                    image=self.image_ref, flavor=self.flavor_ref
                )
            )
        self.ssh_user = CONF.compute.image_ssh_user
        LOG.debug('Starting test for i:{image}, f:{flavor}. '
                  'user: {ssh_user}'.format(
                      image=self.image_ref, flavor=self.flavor_ref,
                      ssh_user=self.ssh_user))

    def boot_instance(self, network):
        self.keypair = self.create_keypair()
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'networks': [
                {'uuid': network['id']},
            ],
            'key_name': self.keypair['name'],
            'security_groups': security_groups,
        }
        self.instance = self.create_server(create_kwargs=create_kwargs)

    def verify_ssh(self):
        # Obtain a floating IP
        floating_ip = self.floating_ips_client.create_floating_ip()
        self.addCleanup(self.delete_wrapper,
                        self.floating_ips_client.delete_floating_ip,
                        floating_ip['id'])
        # Attach a floating IP
        self.floating_ips_client.associate_floating_ip_to_server(
            floating_ip['ip'], self.instance['id'])
        # Check ssh
        ssh_client = self.get_remote_client(
            server_or_ip=floating_ip['ip'],
            username=self.ssh_user,
            private_key=self.keypair['private_key'])
        _, share = self.shares_client.get_share(self.share['id'])
        server_ip = share['export_location'].split(":")[0]
        ssh_client.exec_command("ping -c 1 %s" % server_ip)

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

    def create_share(self, share_net_id):
        self.share = self._create_share(share_protocol=self.protocol,
                                        share_network_id=share_net_id)

    @test.services('compute', 'network')
    def test_server_basicops(self):
        self.security_group = self._create_security_group()
        self.create_share_network()
        self.create_share(self.share_net['id'])
        self.boot_instance(self.net)
        self._allow_access(self.share['id'])
        self.verify_ssh()
        self.servers_client.delete_server(self.instance['id'])
