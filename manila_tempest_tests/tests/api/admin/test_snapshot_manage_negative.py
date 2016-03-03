# Copyright 2015 EMC Corporation.
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

CONF = config.CONF


class ManageNFSSnapshotNegativeTest(base.BaseSharesAdminTest):
    protocol = 'nfs'

    @classmethod
    @base.skip_if_microversion_lt("2.12")
    @testtools.skipIf(
        CONF.share.multitenancy_enabled,
        "Only for driver_handles_share_servers = False driver mode.")
    @testtools.skipUnless(
        CONF.share.run_manage_unmanage_snapshot_tests,
        "Manage/unmanage snapshot tests are disabled.")
    def resource_setup(cls):
        super(ManageNFSSnapshotNegativeTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)

        # Create share type
        cls.st_name = data_utils.rand_name("tempest-manage-st-name")
        cls.extra_specs = {
            'storage_protocol': CONF.share.capability_storage_protocol,
            'driver_handles_share_servers': False,
            'snapshot_support': six.text_type(
                CONF.share.capability_snapshot_support),
        }

        cls.st = cls.create_share_type(
            name=cls.st_name,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs)

        # Create share
        cls.share = cls.create_share(
            share_type_id=cls.st['share_type']['id'],
            share_protocol=cls.protocol
        )

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_manage_not_found(self):
        # Manage snapshot fails
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.manage_snapshot,
                          'fake-share-id',
                          'fake-vol-snap-id',
                          driver_options={})

    @test.attr(type=["gate", "smoke", "negative", ])
    def test_manage_already_exists(self):
        # Manage already existing snapshot fails

        # Create snapshot
        snap = self.create_snapshot_wait_for_active(self.share['id'])
        get_snap = self.shares_v2_client.get_snapshot(snap['id'])
        self.assertEqual(self.share['id'], get_snap['share_id'])
        self.assertIsNotNone(get_snap['provider_location'])

        # Manage snapshot fails
        self.assertRaises(lib_exc.Conflict,
                          self.shares_v2_client.manage_snapshot,
                          self.share['id'],
                          get_snap['provider_location'],
                          driver_options={})

        # Delete snapshot
        self.shares_v2_client.delete_snapshot(get_snap['id'])
        self.shares_client.wait_for_resource_deletion(
            snapshot_id=get_snap['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_snapshot,
                          get_snap['id'])


class ManageCIFSSnapshotNegativeTest(ManageNFSSnapshotNegativeTest):
    protocol = 'cifs'


class ManageGLUSTERFSSnapshotNegativeTest(ManageNFSSnapshotNegativeTest):
    protocol = 'glusterfs'


class ManageHDFSSnapshotNegativeTest(ManageNFSSnapshotNegativeTest):
    protocol = 'hdfs'
