# Copyright 2015 Andrew Kerr
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

from tempest import config
from tempest import test

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class ShareInstancesTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ShareInstancesTest, cls).resource_setup()
        cls.share = cls.create_share()

    @test.attr(type=["gate", ])
    def test_get_instances_of_share_v2_3(self):
        """Test that we get only the 1 share instance back for the share."""
        share_instances = self.shares_v2_client.get_instances_of_share(
            self.share['id'], version='2.3'
        )

        self.assertEqual(1, len(share_instances),
                         'Too many share instances found; expected 1, '
                         'found %s' % len(share_instances))

        si = share_instances[0]
        self.assertEqual(self.share['id'], si['share_id'],
                         'Share instance %s has incorrect share id value; '
                         'expected %s, got %s.' % (si['id'],
                                                   self.share['id'],
                                                   si['share_id']))

    @test.attr(type=["gate", ])
    def test_list_share_instances_v2_3(self):
        """Test that we get at least the share instance back for the share."""
        share_instances = self.shares_v2_client.get_instances_of_share(
            self.share['id'], version='2.3'
        )

        share_ids = [si['share_id'] for si in share_instances]

        msg = 'Share instance for share %s was not found.' % self.share['id']
        self.assertIn(self.share['id'], share_ids, msg)

    def _get_share_instance(self, version):
        """Test that we get the proper keys back for the instance."""
        share_instances = self.shares_v2_client.get_instances_of_share(
            self.share['id'], version=version,
        )

        si = self.shares_v2_client.get_share_instance(
            share_instances[0]['id'], version=version)

        expected_keys = [
            'host', 'share_id', 'id', 'share_network_id', 'status',
            'availability_zone', 'share_server_id', 'created_at',
        ]
        if utils.is_microversion_lt(version, '2.9'):
            expected_keys.extend(["export_location", "export_locations"])
        if utils.is_microversion_ge(version, '2.10'):
            expected_keys.append("access_rules_status")
        expected_keys = sorted(expected_keys)
        actual_keys = sorted(si.keys())
        self.assertEqual(expected_keys, actual_keys,
                         'Share instance %s returned incorrect keys; '
                         'expected %s, got %s.' % (
                             si['id'], expected_keys, actual_keys))

    @test.attr(type=["gate", ])
    def test_get_share_instance_v2_3(self):
        self._get_share_instance('2.3')

    @test.attr(type=["gate", ])
    def test_get_share_instance_v2_9(self):
        self._get_share_instance('2.9')

    @test.attr(type=["gate", ])
    def test_get_share_instance_v2_10(self):
        self._get_share_instance('2.10')
