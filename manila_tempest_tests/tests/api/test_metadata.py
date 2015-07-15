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

from tempest import test  # noqa

from manila_tempest_tests.tests.api import base


class SharesMetadataTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(SharesMetadataTest, cls).resource_setup()
        cls.share = cls.create_share()

    @test.attr(type=["gate", ])
    def test_set_metadata_in_share_creation(self):

        md = {u"key1": u"value1", u"key2": u"value2", }

        # create share with metadata
        share = self.create_share(metadata=md, cleanup_in_class=False)

        # get metadata of share
        metadata = self.shares_client.get_metadata(share["id"])

        # verify metadata
        self.assertEqual(md, metadata)

    @test.attr(type=["gate", ])
    def test_set_get_delete_metadata(self):

        md = {u"key3": u"value3", u"key4": u"value4", }

        # create share
        share = self.create_share(cleanup_in_class=False)

        # set metadata
        self.shares_client.set_metadata(share["id"], md)

        # read metadata
        get_md = self.shares_client.get_metadata(share["id"])

        # verify metadata
        self.assertEqual(md, get_md)

        # delete metadata
        for key in md.keys():
            self.shares_client.delete_metadata(share["id"], key)

        # verify deletion of metadata
        get_metadata = self.shares_client.get_metadata(share["id"])
        self.assertEqual({}, get_metadata)

    @test.attr(type=["gate", ])
    def test_set_and_update_metadata_by_key(self):

        md1 = {u"key5": u"value5", u"key6": u"value6", }
        md2 = {u"key7": u"value7", u"key8": u"value8", }

        # create share
        share = self.create_share(cleanup_in_class=False)

        # set metadata
        self.shares_client.set_metadata(share["id"], md1)

        # update metadata
        self.shares_client.update_all_metadata(share["id"], md2)

        # get metadata
        get_md = self.shares_client.get_metadata(share["id"])

        # verify metadata
        self.assertEqual(md2, get_md)

    @test.attr(type=["gate", ])
    def test_set_metadata_min_size_key(self):
        data = {"k": "value"}

        self.shares_client.set_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data['k'], body_get.get('k'))

    @test.attr(type=["gate", ])
    def test_set_metadata_max_size_key(self):
        max_key = "k" * 255
        data = {max_key: "value"}

        self.shares_client.set_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertIn(max_key, body_get)
        self.assertEqual(data[max_key], body_get.get(max_key))

    @test.attr(type=["gate", ])
    def test_set_metadata_min_size_value(self):
        data = {"key": "v"}

        self.shares_client.set_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data['key'], body_get['key'])

    @test.attr(type=["gate", ])
    def test_set_metadata_max_size_value(self):
        max_value = "v" * 1023
        data = {"key": max_value}

        self.shares_client.set_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data['key'], body_get['key'])

    @test.attr(type=["gate", ])
    def test_upd_metadata_min_size_key(self):
        data = {"k": "value"}

        self.shares_client.update_all_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data, body_get)

    @test.attr(type=["gate", ])
    def test_upd_metadata_max_size_key(self):
        max_key = "k" * 255
        data = {max_key: "value"}

        self.shares_client.update_all_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data, body_get)

    @test.attr(type=["gate", ])
    def test_upd_metadata_min_size_value(self):
        data = {"key": "v"}

        self.shares_client.update_all_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data, body_get)

    @test.attr(type=["gate", ])
    def test_upd_metadata_max_size_value(self):
        max_value = "v" * 1023
        data = {"key": max_value}

        self.shares_client.update_all_metadata(self.share["id"], data)

        body_get = self.shares_client.get_metadata(self.share["id"])
        self.assertEqual(data, body_get)
