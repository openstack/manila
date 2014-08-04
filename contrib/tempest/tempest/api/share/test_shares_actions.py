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
from tempest.common.utils import data_utils
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class SharesTest(base.BaseSharesTest):
    """Covers share functionality, that doesn't related to share type."""

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(SharesTest, cls).setUpClass()
        # create share
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        __, cls.share = cls.create_share(name=cls.share_name,
                                         description=cls.share_desc,
                                         size=cls.share_size)
        # create snapshot
        cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
        cls.snap_desc = data_utils.rand_name("tempest-snapshot-description")
        __, cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"],
                                                           cls.snap_name,
                                                           cls.snap_desc)

    @test.attr(type=["gate", ])
    def test_get_share(self):

        # get share
        resp, share = self.shares_client.get_share(self.share['id'])

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        expected_keys = ["status", "description", "links", "availability_zone",
                         "created_at", "export_location", "share_proto",
                         "name", "snapshot_id", "id", "size"]
        actual_keys = share.keys()
        [self.assertIn(key, actual_keys) for key in expected_keys]

        # verify values
        msg = "Expected name: '%s', actual name: '%s'" % (self.share_name,
                                                          share["name"])
        self.assertEqual(self.share_name, str(share["name"]), msg)

        msg = "Expected description: '%s', "\
              "actual description: '%s'" % (self.share_desc,
                                            share["description"])
        self.assertEqual(self.share_desc, str(share["description"]), msg)

        msg = "Expected size: '%s', actual size: '%s'" % (self.share_size,
                                                          share["size"])
        self.assertEqual(self.share_size, int(share["size"]), msg)

    @test.attr(type=["gate", ])
    def test_list_shares(self):

        # list shares
        resp, shares = self.shares_client.list_shares()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["name", "id", "links"]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in shares if sid["id"] in self.share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail(self):

        # list shares
        resp, shares = self.shares_client.list_shares_with_detail()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = [
            "status", "description", "links", "availability_zone",
            "created_at", "export_location", "share_proto", "host",
            "name", "snapshot_id", "id", "size", "project_id",
        ]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in shares if sid["id"] in self.share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_existed_name(self):
        # list shares by name, at least one share is expected
        params = {"name": self.share_name}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(shares[0]["name"], self.share_name)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_name(self):
        # list shares by fake name, no shares are expected
        params = {"name": data_utils.rand_name("fake-nonexistent-name")}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(len(shares), 0)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_active_status(self):
        # list shares by active status, at least one share is expected
        params = {"status": "available"}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(share["status"], params["status"])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_status(self):
        # list shares by fake status, no shares are expected
        params = {"status": 'fake'}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(len(shares), 0)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_all_tenants(self):
        # non-admin user can get shares only from his project
        params = {"all_tenants": 1}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertTrue(len(shares) > 0)

        # get share with detailed info, we need its 'project_id'
        __, share = self.shares_client.get_share(self.share["id"])
        project_id = share["project_id"]
        for share in shares:
            self.assertEqual(share["project_id"], project_id)

    @test.attr(type=["gate", ])
    def test_get_snapshot(self):

        # get snapshot
        resp, get = self.shares_client.get_snapshot(self.snap["id"])

        # verify data
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        expected_keys = ["status", "links", "share_id", "name",
                         "export_location", "share_proto", "created_at",
                         "description", "id", "share_size"]
        actual_keys = get.keys()
        [self.assertIn(key, actual_keys) for key in expected_keys]

        # verify data
        msg = "Expected name: '%s', actual name: '%s'" % (self.snap_name,
                                                          get["name"])
        self.assertEqual(self.snap_name, get["name"], msg)

        msg = "Expected description: '%s', "\
              "actual description: '%s'" % (self.snap_desc, get["description"])
        self.assertEqual(self.snap_desc, get["description"], msg)

        msg = "Expected share_id: '%s', "\
              "actual share_id: '%s'" % (self.share["id"], get["share_id"])
        self.assertEqual(self.share["id"], get["share_id"], msg)

    @test.attr(type=["gate", ])
    def test_list_snapshots(self):

        # list share snapshots
        resp, snaps = self.shares_client.list_snapshots()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["id", "name", "links"]
        [self.assertIn(key, sn.keys()) for sn in snaps for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(1, len(gen), msg)

    @test.attr(type=["gate", ])
    def test_list_snapshots_with_detail(self):

        # list share snapshots
        resp, snaps = self.shares_client.list_snapshots_with_detail()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["status", "links", "share_id", "name",
                "export_location", "share_proto", "created_at",
                "description", "id", "share_size"]
        [self.assertIn(key, sn.keys()) for sn in snaps for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)


class SharesRenameTest(base.BaseSharesTest):

    @classmethod
    @test.safe_setup
    def setUpClass(cls):
        super(SharesRenameTest, cls).setUpClass()

        # create share
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        __, cls.share = cls.create_share(name=cls.share_name,
                                         description=cls.share_desc,
                                         size=cls.share_size)
        # create snapshot
        cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
        cls.snap_desc = data_utils.rand_name("tempest-snapshot-description")
        __, cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"],
                                                           cls.snap_name,
                                                           cls.snap_desc)

    @test.attr(type=["gate", ])
    def test_rename_share(self):

        # get share
        __, share = self.shares_client.get_share(self.share['id'])
        self.assertEqual(self.share_name, share["name"])
        self.assertEqual(self.share_desc, share["description"])

        # rename share
        new_name = data_utils.rand_name("tempest-new-name")
        new_desc = data_utils.rand_name("tempest-new-description")
        resp, renamed = self.shares_client.rename(share["id"],
                                                  new_name,
                                                  new_desc)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(new_name, renamed["name"])
        self.assertEqual(new_desc, renamed["description"])

        # get share
        resp, share = self.shares_client.get_share(self.share['id'])
        self.assertEqual(new_name, share["name"])
        self.assertEqual(new_desc, share["description"])

    @test.attr(type=["gate", ])
    def test_rename_snapshot(self):

        # get snapshot
        __, get = self.shares_client.get_snapshot(self.snap["id"])
        self.assertEqual(self.snap_name, get["name"])
        self.assertEqual(self.snap_desc, get["description"])

        # rename snapshot
        new_name = data_utils.rand_name("tempest-new-name-for-snapshot")
        new_desc = data_utils.rand_name("tempest-new-description-for-snapshot")
        resp, renamed = self.shares_client.rename_snapshot(self.snap["id"],
                                                           new_name,
                                                           new_desc)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(new_name, renamed["name"])
        self.assertEqual(new_desc, renamed["description"])

        # get snapshot
        resp, get = self.shares_client.get_snapshot(self.snap["id"])
        self.assertEqual(new_name, get["name"])
        self.assertEqual(new_desc, get["description"])
