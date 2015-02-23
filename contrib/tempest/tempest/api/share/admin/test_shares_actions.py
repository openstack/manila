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

import testtools  # noqa

from tempest.api.share import base
from tempest.common.utils import data_utils
from tempest import config_share as config
from tempest import test

CONF = config.CONF


class SharesActionsAdminTest(base.BaseSharesAdminTest):
    """Covers share functionality, that doesn't related to share type."""

    @classmethod
    def resource_setup(cls):
        super(SharesActionsAdminTest, cls).resource_setup()

        # create share type for share filtering purposes
        cls.st_name = data_utils.rand_name("tempest-st-name")
        cls.extra_specs = {'storage_protocol': CONF.share.storage_protocol}
        __, cls.st = cls.create_share_type(
            name=cls.st_name,
            cleanup_in_class=True,
            extra_specs=cls.extra_specs,
        )

        # create share
        cls.share_name = data_utils.rand_name("tempest-share-name")
        cls.share_desc = data_utils.rand_name("tempest-share-description")
        cls.metadata = {
            'foo_key_share_1': 'foo_value_share_1',
            'bar_key_share_1': 'foo_value_share_1',
        }
        cls.share_size = 1
        __, cls.share = cls.create_share(
            name=cls.share_name,
            description=cls.share_desc,
            size=cls.share_size,
            metadata=cls.metadata,
            share_type_id=cls.st['share_type']['id'],
        )

        # create snapshot
        cls.snap_name = data_utils.rand_name("tempest-snapshot-name")
        cls.snap_desc = data_utils.rand_name("tempest-snapshot-description")
        __, cls.snap = cls.create_snapshot_wait_for_active(cls.share["id"],
                                                           cls.snap_name,
                                                           cls.snap_desc)

        # create second share from snapshot for purposes of sorting and
        # snapshot filtering
        cls.share_name2 = data_utils.rand_name("tempest-share-name")
        cls.share_desc2 = data_utils.rand_name("tempest-share-description")
        cls.metadata2 = {
            'foo_key_share_2': 'foo_value_share_2',
            'bar_key_share_2': 'foo_value_share_2',
        }
        __, cls.share2 = cls.create_share(
            name=cls.share_name2,
            description=cls.share_desc2,
            size=cls.share_size,
            metadata=cls.metadata2,
            snapshot_id=cls.snap['id'],
        )

    @test.attr(type=["gate", ])
    def test_get_share(self):

        # get share
        resp, share = self.shares_client.get_share(self.share['id'])

        # verify response
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

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
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

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
        resp, shares = self.shares_client.list_shares_with_detail()

        # verify response
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

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
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertDictContainsSubset(
                filters['metadata'], share['metadata'])
        self.assertFalse(self.share2['id'] in [s['id'] for s in shares])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_extra_specs(self):
        filters = {"extra_specs": self.extra_specs}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        shares_ids = [s["id"] for s in shares]
        self.assertTrue(self.share["id"] in shares_ids)
        self.assertFalse(self.share2["id"] in shares_ids)
        for share in shares:
            __, st_list = self.shares_client.list_share_types()
            # find its name or id, get id
            sts = st_list["share_types"]
            st_id = None
            for st in sts:
                if share["share_type"] in [st["id"], st["name"]]:
                    st_id = st["id"]
                    break
            if st_id is None:
                raise ValueError(
                    "Share '%(s_id)s' listed with extra_specs filter has "
                    "nonexistent share type '%(st)s'." % {
                        "s_id": share["id"], "st": share["share_type"]}
                )
            __, extra_specs = self.shares_client.list_share_types_extra_specs(
                st_id)
            self.assertDictContainsSubset(filters["extra_specs"], extra_specs)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_share_type_id(self):
        filters = {'share_type_id': self.st['share_type']['id']}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            __, st_list = self.shares_client.list_share_types()
            # find its name or id, get id
            sts = st_list["share_types"]
            st_id = None
            for st in sts:
                if share["share_type"] in [st["id"], st["name"]]:
                    st_id = st["id"]
                    break
            if st_id is None:
                raise ValueError(
                    "Share '%(s_id)s' listed with share_type_id filter has "
                    "nonexistent share type '%(st)s'." % {
                        "s_id": share["id"], "st": share["share_type"]}
                )
            self.assertEqual(
                filters['share_type_id'], st_id)
        self.assertFalse(self.share2['id'] in [s['id'] for s in shares])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_host(self):
        __, base_share = self.shares_client.get_share(self.share['id'])
        filters = {'host': base_share['host']}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(filters['host'], share['host'])

    @test.attr(type=["gate", ])
    @testtools.skipIf(
        not CONF.share.multitenancy_enabled, "Only for multitenancy.")
    def test_list_shares_with_detail_filter_by_share_network_id(self):
        __, base_share = self.shares_client.get_share(self.share['id'])
        filters = {'share_network_id': base_share['share_network_id']}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 1)
        for share in shares:
            self.assertEqual(
                filters['share_network_id'], share['share_network_id'])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_snapshot_id(self):
        filters = {'snapshot_id': self.snap['id']}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(filters['snapshot_id'], share['snapshot_id'])
        self.assertFalse(self.share['id'] in [s['id'] for s in shares])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_with_asc_sorting(self):
        filters = {'sort_key': 'created_at', 'sort_dir': 'asc'}

        # list shares
        __, shares = self.shares_client.list_shares_with_detail(params=filters)

        # verify response
        self.assertTrue(len(shares) > 0)
        sorted_list = [share['created_at'] for share in shares]
        self.assertEqual(sorted_list, sorted(sorted_list))

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_existed_name(self):
        # list shares by name, at least one share is expected
        params = {"name": self.share_name}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(shares[0]["name"], self.share_name)

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_name(self):
        # list shares by fake name, no shares are expected
        params = {"name": data_utils.rand_name("fake-nonexistent-name")}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(shares))

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_active_status(self):
        # list shares by active status, at least one share is expected
        params = {"status": "available"}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertTrue(len(shares) > 0)
        for share in shares:
            self.assertEqual(share["status"], params["status"])

    @test.attr(type=["gate", ])
    def test_list_shares_with_detail_filter_by_fake_status(self):
        # list shares by fake status, no shares are expected
        params = {"status": 'fake'}
        resp, shares = self.shares_client.list_shares_with_detail(params)
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertEqual(0, len(shares))

    @test.attr(type=["gate", ])
    def test_get_snapshot(self):

        # get snapshot
        resp, get = self.shares_client.get_snapshot(self.snap["id"])

        # verify data
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

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
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

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
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)

        # verify keys
        keys = ["status", "links", "share_id", "name",
                "export_location", "share_proto", "created_at",
                "description", "id", "share_size"]
        [self.assertIn(key, sn.keys()) for sn in snaps for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in self.snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(1, len(gen), msg)
