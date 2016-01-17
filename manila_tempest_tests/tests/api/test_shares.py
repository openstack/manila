# Copyright 2014 mirantis Inc.
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
from tempest_lib import exceptions as lib_exc  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class SharesNFSTest(base.BaseSharesTest):
    """Covers share functionality, that is related to NFS share type."""
    protocol = "nfs"

    @classmethod
    def resource_setup(cls):
        super(SharesNFSTest, cls).resource_setup()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)
        cls.share = cls.create_share(cls.protocol)

    def _create_delete_share(self, version):

        # create share
        share = self.create_share(
            self.protocol, version=six.text_type(version))
        detailed_elements = {'name', 'id', 'availability_zone',
                             'description', 'export_location', 'project_id',
                             'host', 'created_at', 'share_proto', 'metadata',
                             'size', 'snapshot_id', 'share_network_id',
                             'status', 'share_type', 'volume_type', 'links',
                             'is_public'}
        if version > 2.2:
            detailed_elements.add('snapshot_support')
        self.assertTrue(detailed_elements.issubset(share.keys()),
                        'At least one expected element missing from share '
                        'response. Expected %(expected)s, got %(actual)s.' % {
                            "expected": detailed_elements,
                            "actual": share.keys()})
        self.assertFalse(share['is_public'])

        # The 'status' of the share returned by the create API must be
        # the default value - 'creating'.
        self.assertEqual('creating', share['status'])

        # delete share
        self.shares_client.delete_share(share['id'])
        self.shares_client.wait_for_resource_deletion(share_id=share['id'])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_share,
                          share['id'])

    @test.attr(type=["gate", ])
    def test_create_delete_share_without_snapshot_support_feature(self):
        self._create_delete_share(2.1)

    @test.attr(type=["gate", ])
    def test_create_delete_share_with_snapshot_support_feature(self):
        self._create_delete_share(2.2)

    @test.attr(type=["gate", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_delete_snapshot(self):

        # create snapshot
        snap = self.create_snapshot_wait_for_active(self.share["id"])
        detailed_elements = {'name', 'id', 'description',
                             'created_at', 'share_proto', 'size', 'share_size',
                             'share_id', 'status', 'links'}
        self.assertTrue(detailed_elements.issubset(snap.keys()),
                        'At least one expected element missing from snapshot '
                        'response. Expected %(expected)s, got %(actual)s.' % {
                            "expected": detailed_elements,
                            "actual": snap.keys()})

        # delete snapshot
        self.shares_client.delete_snapshot(snap["id"])
        self.shares_client.wait_for_resource_deletion(snapshot_id=snap["id"])
        self.assertRaises(lib_exc.NotFound,
                          self.shares_client.get_snapshot, snap['id'])

    @test.attr(type=["gate", "smoke", ])
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_share_from_snapshot(self):
        # If multitenant driver used, share_network will be provided by default

        # create snapshot
        snap = self.create_snapshot_wait_for_active(
            self.share["id"], cleanup_in_class=False)

        # create share from snapshot
        s2 = self.create_share(
            self.protocol, snapshot_id=snap["id"], cleanup_in_class=False)

        # The 'status' of the share returned by the create API must be
        # the default value - 'creating'.
        self.assertEqual('creating', s2['status'])

        # verify share, created from snapshot
        get = self.shares_client.get_share(s2["id"])
        msg = "Expected snapshot_id %s as "\
              "source of share %s" % (snap["id"], get["snapshot_id"])
        self.assertEqual(get["snapshot_id"], snap["id"], msg)

    @test.attr(type=["gate", "smoke", ])
    @testtools.skipIf(not CONF.share.multitenancy_enabled,
                      "Only for multitenancy.")
    @testtools.skipUnless(CONF.share.run_snapshot_tests,
                          "Snapshot tests are disabled.")
    def test_create_share_from_snapshot_share_network_not_provided(self):
        # We expect usage of share network from parent's share
        # when creating share from snapshot using multitenant driver.

        # get parent share
        parent = self.shares_client.get_share(self.share["id"])

        # create snapshot
        snap = self.create_snapshot_wait_for_active(
            self.share["id"], cleanup_in_class=False)

        # create share from snapshot
        child = self.create_share(
            self.protocol, snapshot_id=snap["id"], cleanup_in_class=False)

        # The 'status' of the share returned by the create API must be
        # the default value - 'creating'.
        self.assertEqual('creating', child['status'])

        # verify share, created from snapshot
        get = self.shares_client.get_share(child["id"])
        keys = {
            "share": self.share["id"],
            "actual_sn": get["share_network_id"],
            "expected_sn": parent["share_network_id"],
        }
        msg = ("Expected share_network_id %(expected_sn)s for"
               "share %(share)s, but %(actual_sn)s found." % keys)
        self.assertEqual(
            get["share_network_id"], parent["share_network_id"], msg)


class SharesCIFSTest(SharesNFSTest):
    """Covers share functionality, that is related to CIFS share type."""
    protocol = "cifs"


class SharesGLUSTERFSTest(SharesNFSTest):
    """Covers share functionality that is related to GLUSTERFS share type."""
    protocol = "glusterfs"


class SharesHDFSTest(SharesNFSTest):
    """Covers share functionality that is related to HDFS share type."""
    protocol = "hdfs"
