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
from tempest import config  # noqa
from tempest import test  # noqa
from tempest_lib.common.utils import data_utils  # noqa
from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

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
        # Create two shares in parallel
        cls.shares = cls.create_shares([creation_data, creation_data])

        # Load all share data (host, etc.)
        cls.share1 = cls.shares_v2_client.get_share(cls.shares[0]['id'])
        cls.share2 = cls.shares_v2_client.get_share(cls.shares[1]['id'])

        # Unmanage shares from manila
        for share_id in (cls.share1['id'], cls.share2['id']):
            cls.shares_v2_client.unmanage_share(share_id)
            cls.shares_v2_client.wait_for_resource_deletion(share_id=share_id)

    @test.attr(type=["gate", "smoke"])
    def test_manage(self):
        name = "Name for 'managed' share that had ID %s" % self.share1["id"]
        description = "Description for 'managed' share"

        # Manage share
        share = self.shares_v2_client.manage_share(
            service_host=self.share1['host'],
            export_path=self.share1['export_locations'][0],
            protocol=self.share1['share_proto'],
            share_type_id=self.st['share_type']['id'],
            name=name,
            description=description,
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
        self.assertEqual(self.share1['host'], get['host'])
        self.assertEqual(self.share1['share_proto'], get['share_proto'])
        self.assertEqual(self.st['share_type']['name'], get['share_type'])

        get = self.shares_v2_client.get_share(share['id'], version="2.6")
        self.assertEqual(self.st['share_type']['id'], get['share_type'])

        # Delete share
        self.shares_v2_client.delete_share(share['id'])
        self.shares_v2_client.wait_for_resource_deletion(share_id=share['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share,
                          share['id'])

    @test.attr(type=["gate", "smoke"])
    def test_manage_retry(self):
        # Manage share with invalid parameters
        share = None
        parameters = [(self.st_invalid['share_type']['id'], 'manage_error'),
                      (self.st['share_type']['id'], 'available')]

        for share_type_id, status in parameters:
            share = self.shares_v2_client.manage_share(
                service_host=self.share2['host'],
                export_path=self.share2['export_locations'][0],
                protocol=self.share2['share_proto'],
                share_type_id=share_type_id)

            # Add managed share to cleanup queue
            self.method_resources.insert(
                0, {'type': 'share', 'id': share['id'],
                    'client': self.shares_v2_client})

            # Wait for success
            self.shares_v2_client.wait_for_share_status(share['id'], status)

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
