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


class ManageNFSSnapshotTest(base.BaseSharesAdminTest):
    protocol = 'nfs'

    # NOTE(vponomaryov): be careful running these tests using generic driver
    # because cinder volume snapshots won't be deleted.

    @classmethod
    @base.skip_if_microversion_lt("2.12")
    @testtools.skipIf(
        CONF.share.multitenancy_enabled,
        "Only for driver_handles_share_servers = False driver mode.")
    @testtools.skipUnless(
        CONF.share.run_manage_unmanage_snapshot_tests,
        "Manage/unmanage snapshot tests are disabled.")
    def resource_setup(cls):
        super(ManageNFSSnapshotTest, cls).resource_setup()
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

        creation_data = {'kwargs': {
            'share_type_id': cls.st['share_type']['id'],
            'share_protocol': cls.protocol,
        }}

        # Data for creating shares
        data = [creation_data]
        shares_created = cls.create_shares(data)

        cls.snapshot = None
        cls.shares = []
        # Load all share data (host, etc.)
        for share in shares_created:
            cls.shares.append(cls.shares_v2_client.get_share(share['id']))
            # Create snapshot
            snap_name = data_utils.rand_name("tempest-snapshot-name")
            snap_desc = data_utils.rand_name(
                "tempest-snapshot-description")
            snap = cls.create_snapshot_wait_for_active(
                share['id'], snap_name, snap_desc)
            cls.snapshot = cls.shares_v2_client.get_snapshot(snap['id'])
            # Unmanage snapshot
            cls.shares_v2_client.unmanage_snapshot(snap['id'])
            cls.shares_client.wait_for_resource_deletion(
                snapshot_id=snap['id'])

    def _test_manage(self, snapshot, version=CONF.share.max_api_microversion):
        name = ("Name for 'managed' snapshot that had ID %s" %
                snapshot['id'])
        description = "Description for 'managed' snapshot"

        # Manage snapshot
        share_id = snapshot['share_id']
        snapshot = self.shares_v2_client.manage_snapshot(
            share_id,
            snapshot['provider_location'],
            name=name,
            description=description,
            driver_options={}
        )

        # Add managed snapshot to cleanup queue
        self.method_resources.insert(
            0, {'type': 'snapshot', 'id': snapshot['id'],
                'client': self.shares_v2_client})

        # Wait for success
        self.shares_v2_client.wait_for_snapshot_status(snapshot['id'],
                                                       'available')

        # Verify data of managed snapshot
        get_snapshot = self.shares_v2_client.get_snapshot(snapshot['id'])
        self.assertEqual(name, get_snapshot['name'])
        self.assertEqual(description, get_snapshot['description'])
        self.assertEqual(snapshot['share_id'], get_snapshot['share_id'])
        self.assertEqual(snapshot['provider_location'],
                         get_snapshot['provider_location'])

        # Delete snapshot
        self.shares_v2_client.delete_snapshot(get_snapshot['id'])
        self.shares_client.wait_for_resource_deletion(
            snapshot_id=get_snapshot['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_snapshot,
                          get_snapshot['id'])

    @test.attr(type=["gate", "smoke"])
    def test_manage(self):
        # Manage snapshot
        self._test_manage(snapshot=self.snapshot)


class ManageCIFSSnapshotTest(ManageNFSSnapshotTest):
    protocol = 'cifs'


class ManageGLUSTERFSSnapshotTest(ManageNFSSnapshotTest):
    protocol = 'glusterfs'


class ManageHDFSSnapshotTest(ManageNFSSnapshotTest):
    protocol = 'hdfs'
