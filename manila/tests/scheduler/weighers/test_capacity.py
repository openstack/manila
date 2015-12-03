# Copyright 2011-2012 OpenStack LLC.
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
"""
Tests For Capacity Weigher.
"""

import mock
from oslo_config import cfg

from manila import context
from manila.scheduler.weighers import base_host
from manila.scheduler.weighers import capacity
from manila.share import utils
from manila import test
from manila.tests.scheduler import fakes

CONF = cfg.CONF


class CapacityWeigherTestCase(test.TestCase):
    def setUp(self):
        super(CapacityWeigherTestCase, self).setUp()
        self.host_manager = fakes.FakeHostManager()
        self.weight_handler = base_host.HostWeightHandler(
            'manila.scheduler.weighers')

    def _get_weighed_host(self, hosts, weight_properties=None, index=0):
        if weight_properties is None:
            weight_properties = {'size': 1}
        return self.weight_handler.get_weighed_objects(
            [capacity.CapacityWeigher],
            hosts,
            weight_properties)[index]

    @mock.patch('manila.db.api.IMPL.service_get_all_by_topic')
    def _get_all_hosts(self, _mock_service_get_all_by_topic, disabled=False):
        ctxt = context.get_admin_context()
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic,
                                         disabled=disabled)
        host_states = self.host_manager.get_all_host_states_share(ctxt)
        _mock_service_get_all_by_topic.assert_called_once_with(
            ctxt, CONF.share_topic)
        return host_states

    # NOTE(xyang): If thin_provisioning = True and
    # max_over_subscription_ratio >= 1, use the following formula:
    # free = math.floor(total * host_state.max_over_subscription_ratio
    #        - host_state.provisioned_capacity_gb
    #        - total * reserved)
    # Otherwise, use the following formula:
    # free = math.floor(free_space - total * reserved)
    def test_default_of_spreading_first(self):
        hostinfo_list = self._get_all_hosts()

        # host1: thin_provisioning = False
        #        free_capacity_gb = 1024
        #        free = math.floor(1024 - 1024 * 0.1) = 921.0
        #        weight = 0.40
        # host2: thin_provisioning = True
        #        max_over_subscription_ratio = 2.0
        #        free_capacity_gb = 300
        #        free = math.floor(2048 * 2.0 - 1748 - 2048 * 0.1)=2143.0
        #        weight = 1.0
        # host3: thin_provisioning = False
        #        free_capacity_gb = 512
        #        free = math.floor(256 - 512 * 0)=256.0
        #        weight = 0.08
        # host4: thin_provisioning = True
        #        max_over_subscription_ratio = 1.0
        #        free_capacity_gb = 200
        #        free = math.floor(2048 * 1.0 - 1848 - 2048 * 0.05) = 97.0
        #        weight = 0.0
        # host5: thin_provisioning = True
        #        max_over_subscription_ratio = 1.5
        #        free_capacity_gb = 500
        #        free = math.floor(2048 * 1.5 - 1548 - 2048 * 0.05) = 1421.0
        #        weight = 0.65
        # host6: thin_provisioning = False
        #        free = inf
        #        weight = 0.0

        # so, host2 should win:
        weighed_host = self._get_weighed_host(hostinfo_list)
        self.assertEqual(1.0, weighed_host.weight)
        self.assertEqual(
            'host2', utils.extract_host(weighed_host.obj.host))

    def test_unknown_is_last(self):
        hostinfo_list = self._get_all_hosts()

        last_host = self._get_weighed_host(hostinfo_list, index=-1)
        self.assertEqual(
            'host6', utils.extract_host(last_host.obj.host))
        self.assertEqual(0.0, last_host.weight)

    def test_capacity_weight_multiplier_negative_1(self):
        self.flags(capacity_weight_multiplier=-1.0)
        hostinfo_list = self._get_all_hosts()

        # host1: thin_provisioning = False
        #        free_capacity_gb = 1024
        #        free = math.floor(1024 - 1024 * 0.1) = 921.0
        #        free * (-1) = -921.0
        #        weight = -0.40
        # host2: thin_provisioning = True
        #        max_over_subscription_ratio = 2.0
        #        free_capacity_gb = 300
        #        free = math.floor(2048 * 2.0-1748-2048 * 0.1) = 2143.0
        #        free * (-1) = -2143.0
        #        weight = -1.0
        # host3: thin_provisioning = False
        #        free_capacity_gb = 512
        #        free = math.floor(256 - 512 * 0) = 256.0
        #        free * (-1) = -256.0
        #        weight = -0.08
        # host4: thin_provisioning = True
        #        max_over_subscription_ratio = 1.0
        #        free_capacity_gb = 200
        #        free = math.floor(2048 * 1.0 - 1848 - 2048 * 0.05) = 97.0
        #        free * (-1) = -97.0
        #        weight = 0.0
        # host5: thin_provisioning = True
        #        max_over_subscription_ratio = 1.5
        #        free_capacity_gb = 500
        #        free = math.floor(2048 * 1.5 - 1548 - 2048 * 0.05) = 1421.0
        #        free * (-1) = -1421.0
        #        weight = -0.65
        # host6: thin_provisioning = False
        #        free = inf
        #        free * (-1) = -inf
        #        weight = 0.0

        # so, host4 should win:
        weighed_host = self._get_weighed_host(hostinfo_list)
        self.assertEqual(0.0, weighed_host.weight)
        self.assertEqual(
            'host4', utils.extract_host(weighed_host.obj.host))

    def test_capacity_weight_multiplier_2(self):
        self.flags(capacity_weight_multiplier=2.0)
        hostinfo_list = self._get_all_hosts()

        # host1: thin_provisioning = False
        #        free_capacity_gb = 1024
        #        free = math.floor(1024-1024*0.1) = 921.0
        #        free * 2 = 1842.0
        #        weight = 0.81
        # host2: thin_provisioning = True
        #        max_over_subscription_ratio = 2.0
        #        free_capacity_gb = 300
        #        free = math.floor(2048 * 2.0 - 1748 - 2048 * 0.1) = 2143.0
        #        free * 2 = 4286.0
        #        weight = 2.0
        # host3: thin_provisioning = False
        #        free_capacity_gb = 512
        #        free = math.floor(256 - 512 * 0) = 256.0
        #        free * 2 = 512.0
        #        weight = 0.16
        # host4: thin_provisioning = True
        #        max_over_subscription_ratio = 1.0
        #        free_capacity_gb = 200
        #        free = math.floor(2048 * 1.0 - 1848 - 2048 * 0.05) = 97.0
        #        free * 2 = 194.0
        #        weight = 0.0
        # host5: thin_provisioning = True
        #        max_over_subscription_ratio = 1.5
        #        free_capacity_gb = 500
        #        free = math.floor(2048 * 1.5 - 1548 - 2048 * 0.05) = 1421.0
        #        free * 2 = 2842.0
        #        weight = 1.29
        # host6: thin_provisioning = False
        #        free = inf
        #        weight = 0.0

        # so, host2 should win:
        weighed_host = self._get_weighed_host(hostinfo_list)
        self.assertEqual(2.0, weighed_host.weight)
        self.assertEqual(
            'host2', utils.extract_host(weighed_host.obj.host))
