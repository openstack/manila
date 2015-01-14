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

from tempest.api.share import base
from tempest import test


class SharesMetadataTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(SharesMetadataTest, cls).resource_setup()
        __, cls.share = cls.create_share()

    @test.attr(type=["gate", ])
    def test_set_metadata_in_share_creation(self):

        md = {u"key1": u"value1", u"key2": u"value2", }

        # create share with metadata
        __, share = self.create_share(metadata=md, cleanup_in_class=False)

        # get metadata of share
        resp, metadata = self.shares_client.get_metadata(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify metadata
        self.assertEqual(md, metadata)

    @test.attr(type=["gate", ])
    def test_set_get_delete_metadata(self):

        md = {u"key3": u"value3", u"key4": u"value4", }

        # create share
        __, share = self.create_share(cleanup_in_class=False)

        # set metadata
        resp, __ = self.shares_client.set_metadata(share["id"], md)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # read metadata
        resp, get_md = self.shares_client.get_metadata(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify metadata
        self.assertEqual(md, get_md)

        # delete metadata
        for key in md.keys():
            resp, __ = self.shares_client.delete_metadata(share["id"], key)
            self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify deletion of metadata
        resp, get_metadata = self.shares_client.get_metadata(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
        self.assertEqual({}, get_metadata)

    @test.attr(type=["gate", ])
    def test_set_and_update_metadata_by_key(self):

        md1 = {u"key5": u"value5", u"key6": u"value6", }
        md2 = {u"key7": u"value7", u"key8": u"value8", }

        # create share
        __, share = self.create_share(cleanup_in_class=False)

        # set metadata
        resp, __ = self.shares_client.set_metadata(share["id"], md1)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # update metadata
        resp, __ = self.shares_client.update_all_metadata(share["id"], md2)
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # get metadata
        resp, get_md = self.shares_client.get_metadata(share["id"])
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

        # verify metadata
        self.assertEqual(md2, get_md)

    @test.attr(type=["gate", ])
    def test_set_metadata_min_size_key(self):
        resp, min = self.shares_client.set_metadata(self.share["id"],
                                                    {"k": "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_set_metadata_max_size_key(self):
        max_key = "k" * 255
        resp, max = self.shares_client.set_metadata(self.share["id"],
                                                    {max_key: "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_set_metadata_min_size_value(self):
        resp, min = self.shares_client.set_metadata(self.share["id"],
                                                    {"key": "v"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_set_metadata_max_size_value(self):
        max_value = "v" * 1023
        resp, body = self.shares_client.set_metadata(self.share["id"],
                                                     {"key": max_value})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_upd_metadata_min_size_key(self):
        resp, body = self.shares_client.update_all_metadata(self.share["id"],
                                                            {"k": "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_upd_metadata_max_size_key(self):
        max_key = "k" * 255
        resp, body = self.shares_client.update_all_metadata(self.share["id"],
                                                            {max_key: "value"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_upd_metadata_min_size_value(self):
        resp, body = self.shares_client.update_all_metadata(self.share["id"],
                                                            {"key": "v"})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)

    @test.attr(type=["gate", ])
    def test_upd_metadata_max_size_value(self):
        max_value = "v" * 1023
        resp, body = self.shares_client.update_all_metadata(self.share["id"],
                                                            {"key": max_value})
        self.assertIn(int(resp["status"]), test.HTTP_SUCCESS)
