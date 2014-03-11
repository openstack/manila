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

from tempest.api.share import base
from tempest import config_share as config
from tempest import exceptions
from tempest import test

CONF = config.CONF


class SharesNFSTest(base.BaseSharesTest):
    """Covers share functionality, that is related to NFS share type."""
    protocol = "nfs"

    @classmethod
    def setUpClass(cls):
        super(SharesNFSTest, cls).setUpClass()
        if cls.protocol not in CONF.share.enable_protocols:
            message = "%s tests are disabled" % cls.protocol
            raise cls.skipException(message)
        __, cls.share = cls.create_share_wait_for_active(cls.protocol)

    @test.attr(type=["gate", ])
    def test_create_delete_share(self):

        # create share
        resp, share = self.create_share_wait_for_active(self.protocol)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # delete share
        resp, __ = self.shares_client.delete_share(share['id'])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_resource_deletion(share_id=share['id'])
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_share,
                          share['id'])

    @test.attr(type=["gate", ])
    def test_create_delete_snapshot(self):

        # create snapshot
        resp, snap = self.create_snapshot_wait_for_active(self.share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # delete snapshot
        resp, __ = self.shares_client.delete_snapshot(snap["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_resource_deletion(snapshot_id=snap["id"])
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_snapshot, snap['id'])

    @test.attr(type=["gate", "smoke", ])
    def test_create_share_from_snapshot(self):

        # create snapshot
        __, snap = self.create_snapshot_wait_for_active(self.share["id"],
                                                        cleanup_in_class=False)

        # crate share from snapshot
        resp, s2 = self.create_share_wait_for_active(self.protocol,
                                                     snapshot_id=snap["id"],
                                                     cleanup_in_class=False)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify share, created from snapshot
        resp, get = self.shares_client.get_share(s2["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        msg = "Expected snapshot_id %s as "\
              "source of share %s" % (snap["id"], get["snapshot_id"])
        self.assertEqual(get["snapshot_id"], snap["id"], msg)


class SharesCIFSTest(SharesNFSTest):
    """Covers share functionality, that is related to CIFS share type."""
    protocol = "cifs"
