# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from tempest.api.shares import base
from tempest.common.utils.data_utils import rand_name
from tempest import exceptions
from tempest import test


class SharesTestJSON(base.BaseSharesTest):

    def tearDown(self):
        super(SharesTestJSON, self).tearDown()
        self.clear_resources()

    @test.attr(type=['positive', ])
    def test_create_delete_share(self):

        # create share
        resp, share = self.create_share_wait_for_active()
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # delete share
        resp, __ = self.shares_client.delete_share(share['id'])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.shares_client.wait_for_resource_deletion(share['id'])
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_share,
                          share['id'])

    @test.attr(type=['positive', ])
    def test_get_share(self):

        # test data
        name = rand_name("rand-share-name-")
        desc = rand_name("rand-share-description-")
        size = 1

        # create share
        resp, share = self.create_share_wait_for_active(name=name,
                                                        description=desc,
                                                        size=size)

        # get share
        resp, share = self.shares_client.get_share(share['id'])

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        expected_keys = ["status", "description", "links", "availability_zone",
                         "created_at", "export_location", "share_proto",
                         "name", "snapshot_id", "id", "size"]
        actual_keys = share.keys()
        [self.assertIn(key, actual_keys) for key in expected_keys]

        # verify values
        msg = "Expected name: '%s', actual name: '%s'" % (name, share["name"])
        self.assertEqual(name, str(share["name"]), msg)

        msg = "Expected description: '%s', "\
              "actual description: '%s'" % (desc, share["description"])
        self.assertEqual(desc, str(share["description"]), msg)

        msg = "Expected size: '%s', actual size: '%s'" % (size, share["size"])
        self.assertEqual(size, int(share["size"]), msg)

    @test.attr(type=['positive', ])
    def test_list_shares(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        # list shares
        resp, shares = self.shares_client.list_shares()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["name", "id", "links"]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in shares if sid["id"] in share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=['positive', 'gate'])
    def test_list_shares_with_detail(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        # list shares
        resp, shares = self.shares_client.list_shares_with_detail()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["status", "description", "links", "availability_zone",
                "created_at", "export_location", "share_proto",
                "name", "snapshot_id", "id", "size"]
        [self.assertIn(key, sh.keys()) for sh in shares for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in shares if sid["id"] in share["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=['positive', ])
    def test_create_delete_snapshot(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        # create snapshot
        resp, snap = self.create_snapshot_wait_for_active(share["id"])

        # delete snapshot
        self.shares_client.delete_snapshot(snap["id"])
        self.shares_client.wait_for_resource_deletion(snap["id"])
        self.assertRaises(exceptions.NotFound,
                          self.shares_client.get_snapshot, snap['id'])

    @test.attr(type=['positive', ])
    def test_get_snapshot(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        #create snapshot
        name = rand_name("tempest-snap-")
        desc = rand_name("tempest-snap-description-")
        resp, snap = self.create_snapshot_wait_for_active(share["id"],
                                                          name, desc)

        # get snapshot
        resp, get = self.shares_client.get_snapshot(snap["id"])

        # verify data
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        expected_keys = ["status", "links", "share_id", "name",
                         "export_location", "share_proto", "created_at",
                         "description", "id", "share_size"]
        actual_keys = get.keys()
        [self.assertIn(key, actual_keys) for key in expected_keys]

        # verify data
        msg = "Expected name: '%s', actual name: '%s'" % (name, get["name"])
        self.assertEqual(name, get["name"], msg)

        msg = "Expected description: '%s', "\
              "actual description: '%s'" % (desc, get["description"])
        self.assertEqual(desc, get["description"], msg)

        msg = "Expected share_id: '%s', "\
              "actual share_id: '%s'" % (name, get["share_id"])
        self.assertEqual(share["id"], get["share_id"], msg)

    @test.attr(type=['positive', ])
    def test_list_snapshots(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        #create snapshot
        resp, snap = self.create_snapshot_wait_for_active(share["id"])

        # list share snapshots
        resp, snaps = self.shares_client.list_snapshots()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify keys
        keys = ["id", "name", "links"]
        [self.assertIn(key, sn.keys()) for sn in snaps for key in keys]

        # our share id in list and have no duplicates
        gen = [sid["id"] for sid in snaps if sid["id"] in snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEquals(1, len(gen), msg)

    @test.attr(type=['positive', 'gate'])
    def test_list_snapshots_with_detail(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        # create snapshot
        resp, snap = self.create_snapshot_wait_for_active(share["id"])

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
        gen = [sid["id"] for sid in snaps if sid["id"] in snap["id"]]
        msg = "expected id lists %s times in share list" % (len(gen))
        self.assertEqual(len(gen), 1, msg)

    @test.attr(type=['positive', 'smoke', 'gate'])
    def test_create_share_from_snapshot(self):

        # create share
        resp, share = self.create_share_wait_for_active()

        # create snapshot
        resp, snap = self.create_snapshot_wait_for_active(share["id"])

        # crate share from snapshot
        resp, s2 = self.create_share_wait_for_active(snapshot_id=snap["id"])

        # verify share, created from snapshot
        resp, get = self.shares_client.get_share(s2["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        msg = "Expected snapshot_id %s as "\
              "source of share %s" % (snap["id"], get["snapshot_id"])
        self.assertEqual(get["snapshot_id"], snap["id"], msg)

    @test.attr(type=['positive', 'smoke', 'gate'])
    def test_extensions(self):

        # get extensions
        resp, extensions = self.shares_client.list_extensions()

        # verify response
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        keys = ['alias', 'updated', 'namespace', 'name', 'description']
        [self.assertIn(key, ext.keys()) for ext in extensions for key in keys]

    @test.attr(type=['positive', ])
    def test_rename_share(self):

        # create share
        _, share = self.create_share_wait_for_active()

        # rename share
        new_name = rand_name("new_name_")
        new_desc = rand_name("new_desc_")
        resp, renamed = self.shares_client.rename(share["id"],
                                                  new_name,
                                                  new_desc)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(new_name, renamed["name"])
        self.assertEqual(new_desc, renamed["description"])

    @test.attr(type=['positive', ])
    def test_rename_snapshot(self):

        # create share
        _, share = self.create_share_wait_for_active()

        # create snapshot
        _, snap = self.create_snapshot_wait_for_active(share["id"])

        # rename snapshot
        new_name = rand_name("new_name_for_snap_")
        new_desc = rand_name("new_desc_for_snap_")
        resp, renamed = self.shares_client.rename_snapshot(snap["id"],
                                                           new_name,
                                                           new_desc)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual(new_name, renamed["name"])
        self.assertEqual(new_desc, renamed["description"])


class SharesTestXML(SharesTestJSON):
    _interface = 'xml'
