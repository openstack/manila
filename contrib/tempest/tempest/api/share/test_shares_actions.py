# Copyright 2014 Mirantis Inc.
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

from tempest_lib.common.utils import data_utils  # noqa
import testtools  # noqa

from tempest.api.share import base
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class SharesActionsTest(base.BaseSharesTest):
    """Covers share functionality, that doesn't related to share type."""

    @classmethod
    def resource_setup(cls):
        super(SharesActionsTest, cls).resource_setup()

        # create share
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.metadata = {
            'foo_key_share_1': 'foo_value_share_1',
            'bar_key_share_1': 'foo_value_share_1',
        }
        cls.share_size = 1
        cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            size=cls.share_size,
            metadata=cls.metadata,
        )

        # create snapshot
        cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
        cls.snap_desc = data_utils.rand_name("tempest-snapshot-description")
        cls.snap = cls.create_snapshot_wait_for_active(
            cls.share["id"], cls.snap_name, cls.snap_desc)

        # create second share from snapshot for purposes of sorting and
        # snapshot filtering
        cls.share_name2 = data_utils.rand_name("tempest-share-name")
        cls.share_desc2 = data_utils.rand_name("tempest-share-description")
        cls.metadata2 = {
            'foo_key_share_2': 'foo_value_share_2',
            'bar_key_share_2': 'foo_value_share_2',
        }
        cls.share2 = cls.create_share(
            name=cls.share_name2,
            description=cls.share_desc2,
            size=cls.share_size,
            metadata=cls.metadata2,
            snapshot_id=cls.snap['id'],
        )

    @test.attr(type=["gate", ])
    def test_get_share(self):

        # get share
        share = self.shares_client.get_share(self.share['id'])

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
        shares = self.shares_client.list_shares()

        # verify keys
        keys = ["name", "id", "links"]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our share id in list and have no duplicates
        for share_id in [self.share["id"], self.share2["id"]]:
            gen = [sid["id"] for sid in shares if sid["id"] in share_id]
            msg = "expected id lists %s times in share list" % (len(gen))
            self.assertEqual(1, len(gen), msg)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail(self):

        # list shares
        shares = self.shares_client.list_shares_with_detail()

        # verify keys
        keys = [
            "status", "description", "links", "availability_zone",
            "created_at", "export_location", "share_proto", "host",
            "name", "snapshot_id", "id", "size", "project_id",
        ]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our shares in list and have no duplicates
        for share_id in [self.share["id"], self.share2["id"]]:
            gen = [sid["id"] for sid in shares if sid["id"] in share_id]
            msg = "expected id lists %s times in share list" % (len(gen))
            self.assertEqual(1, len(gen), msg)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_metadata(self):
        filters = {'metadata': self.metadata}

        # list shares
        shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertDictContainsSubset(
                filters['metadata'], share['metadata'])
        self.assertFalse(self.share2['id'] in [s['id'] for s in shares])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_host(self):
        base_share = self.shares_client.get_share(self.share['id'])
        filters = {'host': base_share['host']}

        # list shares
        shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(filters['host'], share['host'])

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        not CONF.share.multitenancy_enabled, "Only for multitenancy.")
    def test_list_shares_with_detail_filter_by_share_network_id(self):
        base_share = self.shares_client.get_share(self.share['id'])
        filters = {'share_network_id': base_share['share_network_id']}

        # list shares
        shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 1)
        for share in shares:
            self.assertEqual(
                filters['share_network_id'], share['share_network_id'])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_snapshot_id(self):
        filters = {'snapshot_id': self.snap['id']}

        # list shares
        shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(filters['snapshot_id'], share['snapshot_id'])
        self.assertFalse(self.share['id'] in [s['id'] for s in shares])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_with_asc_sorting(self):
        filters = {'sort_key': 'created_at', 'sort_dir': 'asc'}

        # list shares
        shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        sorted_list = [share['created_at'] for share in shares]
        self.assertEqual(sorted_list, sorted(sorted_list))

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_existed_name(self):
        # list shares by name, at least one share is expected
        params = {"name": self.share_name}
        shares = self.shares_client.list_shares_with_detail(params)
        self.assertEqual(shares[0]["name"], self.share_name)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_name(self):
        # list shares by fake name, no shares are expected
        params = {"name": data_utils.rand_name("fake-nonexistent-name")}
        shares = self.shares_client.list_shares_with_detail(params)
        self.assertEqual(len(shares), 0)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_active_status(self):
        # list shares by active status, at least one share is expected
        params = {"status": "available"}
        shares = self.shares_client.list_shares_with_detail(params)
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(share["status"], params["status"])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_status(self):
        # list shares by fake status, no shares are expected
        params = {"status": 'fake'}
        shares = self.shares_client.list_shares_with_detail(params)
        self.assertEqual(len(shares), 0)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_all_tenants(self):
        # non-admin user can get shares only from his project
        params = {"all_tenants": 1}
        shares = self.shares_client.list_shares_with_detail(params)
        self.assertTrue(len(shares) > 0)

        # get share with detailed info, we need its 'project_id'
        share = self.shares_client.get_share(self.share["id"])
        project_id = share["project_id"]
        for share in shares:
            self.assertEqual(share["project_id"], project_id)

    @test.attr(type=["gate", ])
    def test_list_shares_public_with_detail(self):
        public_share = self.shares_client.create_share(
            name='public_share',
            description='public_share_desc',
            size=1,
            is_public=True
        )
        private_share = self.shares_client.create_share(
            name='private_share',
            description='private_share_desc',
            size=1,
            is_public=False
        )

        params = {"is_public": True}
        isolated_client = self.get_client_with_isolated_creds(
            type_of_creds='alt')
        shares = isolated_client.list_shares_with_detail(params)

        keys = [
            "status", "description", "links", "availability_zone",
            "created_at", "export_location", "share_proto", "host",
            "name", "snapshot_id", "id", "size", "project_id", "is_public",
        ]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        gen = [sid["id"] for sid in shares if sid["id"] == public_share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(1, len(gen), msg)

        self.assertFalse(any([s["id"] == private_share["id"] for s in shares]))

    @test.attr(type=["gate", ])
    def test_get_snapshot(self):

        # get snapshot
        get = self.shares_client.get_snapshot(self.snap["id"])

        # verify keys
        expected_keys = ["status", "links", "share_id", "name",
                         "share_proto", "created_at",
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
        snaps = self.shares_client.list_snapshots()

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
        snaps = self.shares_client.list_snapshots_with_detail()

        # verify keys
        keys = ["status", "links", "share_id", "name",
                "share_proto", "created_at",
                "description", "id", "share_size"]
        [self.assertIn(key, sn.keys()) for sn in snaps for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=["gate", ])
    def test_list_snapshots_with_detail_use_limit(self):
        for l, o in [('1', '1'), ('0', '1')]:
            filters = {'limit': l, 'offset': o, 'share_id': self.share['id']}

            # list snapshots
            snaps = self.shares_client.list_snapshots_with_detail(
                params=filters)

            # Our snapshot should not be listed
            self.assertEqual(0, len(snaps))

        # Only our one snapshot should be listed
        snaps = self.shares_client.list_snapshots_with_detail(
            params={'limit': '1', 'offset': '0', 'share_id': self.share['id']})

        self.assertEqual(1, len(snaps['snapshots']))
        self.assertEqual(self.snap['id'], snaps['snapshots'][0]['id'])

    @test.attr(type=["gate", ])
    def test_list_snapshots_with_detail_filter_by_status_and_name(self):
        filters = {'status': 'available', 'name': self.snap_name}

        # list snapshots
        snaps = self.shares_client.list_snapshots_with_detail(
            params=filters)

        # verify response
        self.assertTrue(len(snaps) > 0)
        for snap in snaps:
            self.assertEqual(filters['status'], snap['status'])
            self.assertEqual(filters['name'], snap['name'])

    @test.attr(type=["gate", ])
    def test_list_snapshots_with_detail_and_asc_sorting(self):
        filters = {'sort_key': 'share_id', 'sort_dir': 'asc'}

        # list snapshots
        snaps = self.shares_client.list_snapshots_with_detail(
            params=filters)

        # verify response
        self.assertTrue(len(snaps) > 0)
        sorted_list = [snap['share_id'] for snap in snaps]
        self.assertEqual(sorted_list, sorted(sorted_list))


class SharesRenameTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(SharesRenameTest, cls).resource_setup()

        # create share
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.share_size = 1
        cls.share = cls.create_share(
            name=cls.share_name, description=cls.share_desc,
            size=cls.share_size)

        # create snapshot
        cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
        cls.snap_desc = data_utils.rand_name("tempest-snapshot-description")
        cls.snap = cls.create_snapshot_wait_for_active(
            cls.share["id"], cls.snap_name, cls.snap_desc)

    @test.attr(type=["gate", ])
    def test_update_share(self):

        # get share
        share = self.shares_client.get_share(self.share['id'])
        self.assertEqual(self.share_name, share["name"])
        self.assertEqual(self.share_desc, share["description"])
        self.assertFalse(share["is_public"])

        # update share
        new_name = data_utils.rand_name("tempest-new-name")
        new_desc = data_utils.rand_name("tempest-new-description")
        updated = self.shares_client.update_share(
            share["id"], new_name, new_desc, is_public=True)
        self.assertEqual(new_name, updated["name"])
        self.assertEqual(new_desc, updated["description"])
        self.assertTrue(updated["is_public"])

        # get share
        share = self.shares_client.get_share(self.share['id'])
        self.assertEqual(new_name, share["name"])
        self.assertEqual(new_desc, share["description"])
        self.assertTrue(share["is_public"])

    @test.attr(type=["gate", ])
    def test_rename_snapshot(self):

        # get snapshot
        get = self.shares_client.get_snapshot(self.snap["id"])
        self.assertEqual(self.snap_name, get["name"])
        self.assertEqual(self.snap_desc, get["description"])

        # rename snapshot
        new_name = data_utils.rand_name("tempest-new-name-for-snapshot")
        new_desc = data_utils.rand_name("tempest-new-description-for-snapshot")
        renamed = self.shares_client.rename_snapshot(
            self.snap["id"], new_name, new_desc)
        self.assertEqual(new_name, renamed["name"])
        self.assertEqual(new_desc, renamed["description"])

        # get snapshot
        get = self.shares_client.get_snapshot(self.snap["id"])
        self.assertEqual(new_name, get["name"])
        self.assertEqual(new_desc, get["description"])
