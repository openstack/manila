# Copyright 2015 Mirantis Inc.
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

import six
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test
import testtools

from manila_tempest_tests.tests.api import base
from manila_tempest_tests import utils

CONF = config.CONF


class ManageNFSShareTest(base.BaseSharesAdminTest):
    protocol = 'nfs'

    # NOTE(vponomaryov): be careful running these tests using generic driver
    # because cinder volumes will stay attached to service Nova VM and
    # won't be deleted.

    @classmethod
    @testtools.skipIf(
        CONF.share.multitenancy_enabled,
        "Only for driver_handles_share_servers = False driver mode.")
    @testtools.skipUnless(
        CONF.share.run_manage_unmanage_tests,
        "Manage/unmanage tests are disabled.")
    def resource_setup(cls):
        super(ManageNFSShareTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)

        # Create share types
        cls.st_name = data_utils.rand_name("manage-st-name")
        cls.st_name_invalid = data_utils.rand_name("manage-st-name-invalid")
        cls.extra_specs = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': False,
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
        }
        cls.extra_specs_invalid = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': True,
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
        }

        cls.st = cls.create_share_type(
            name=cls.st_name,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs)

        cls.st_invalid = cls.create_share_type(
            name=cls.st_name_invalid,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs_invalid)

        creation_data = {'kwargs': {
            'share_type_id': cls.st['share_type']['id'],
            'share_protocol': cls.protocol,
        }}

        # Data for creating shares in parallel
        data = [creation_data, creation_data]
        if utils.is_microversion_ge(CONF.share.max_api_microversion, "2.8"):
            data.append(creation_data)
        shares_created = cls.create_shares(data)

        cls.shares = []
        # Load all share data (host, etc.)
        for share in shares_created:
            # Unmanage shares from manila
            cls.shares.append(cls.shares_client.get_share(share['id']))
            cls.shares_client.unmanage_share(share['id'])
            cls.shares_client.wait_for_resource_deletion(
                share_id=share['id'])

    def _test_manage(self, share, is_public=False,
                     version=CONF.share.max_api_microversion):
        name = "Name for 'managed' share that had ID %s" % \
               share['id']
        description = "Description for 'managed' share"

        # Manage share
        share = self.shares_v2_client.manage_share(
            service_host=share['host'],
            export_path=share['export_locations'][0],
            protocol=share['share_proto'],
            share_type_id=self.st['share_type']['id'],
            name=name,
            description=description,
            is_public=is_public,
        )

        # Add managed share to cleanup queue
        self.method_resources.insert(
            0, {'type': 'share', 'id': share['id'],
                'client': self.shares_client})

        # Wait for success
        self.shares_v2_client.wait_for_share_status(share['id'], 'available')

        # Verify data of managed share
        get = self.shares_v2_client.get_share(share['id'], version="2.5")
        self.assertEqual(name, get['name'])
        self.assertEqual(description, get['description'])
        self.assertEqual(share['host'], get['host'])
        self.assertEqual(share['share_proto'], get['share_proto'])
        self.assertEqual(self.st['share_type']['name'], get['share_type'])

        share = self.shares_v2_client.get_share(share['id'], version="2.6")
        self.assertEqual(self.st['share_type']['id'], share['share_type'])

        if utils.is_microversion_ge(version, "2.8"):
            self.assertEqual(is_public, share['is_public'])
        else:
            self.assertFalse(share['is_public'])

        # Delete share
        self.shares_v2_client.delete_share(share['id'])
        self.shares_v2_client.wait_for_resource_deletion(share_id=share['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share,
                          share['id'])

    @base.skip_if_microversion_not_supported("2.8")
    @test.attr(type=["gate", "smoke"])
    def test_manage_with_is_public_True(self):
        self._test_manage(share=self.shares[2], is_public=True)

    @test.attr(type=["gate", "smoke"])
    def test_manage(self):
        # After 'unmanage' operation, share instance should be deleted.
        # Assert not related to 'manage' test, but placed here for
        # resource optimization.
        share_instance_list = self.shares_v2_client.list_share_instances()
        share_ids = [si['share_id'] for si in share_instance_list]
        self.assertNotIn(self.shares[0]['id'], share_ids)

        self._test_manage(share=self.shares[0])

    @test.attr(type=["gate", "smoke"])
    def test_manage_retry(self):
        # Manage share with invalid parameters

        self.assertRaises(
            lib_exc.Conflict,
            self.shares_v2_client.manage_share,
            service_host=self.shares[1]['host'],
            export_path=self.shares[1]['export_locations'][0],
            protocol=self.shares[1]['share_proto'],
            share_type_id=self.st_invalid['share_type']['id'])

        share = self.shares_v2_client.manage_share(
            service_host=self.shares[1]['host'],
            export_path=self.shares[1]['export_locations'][0],
            protocol=self.shares[1]['share_proto'],
            share_type_id=self.st['share_type']['id'])

        self.shares_v2_client.wait_for_share_status(share['id'], 'available')

        # Delete share
        self.shares_v2_client.delete_share(share['id'])
        self.shares_v2_client.wait_for_resource_deletion(share_id=share['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share,
                          share['id'])


class ManageCIFSShareTest(ManageNFSShareTest):
    protocol = 'cifs'


class ManageGLUSTERFSShareTest(ManageNFSShareTest):
    protocol = 'glusterfs'


class ManageHDFSShareTest(ManageNFSShareTest):
    protocol = 'hdfs'


class ManageCephFSShareTest(ManageNFSShareTest):
    protocol = 'cephfs'
