# Copyright (c) 2011 Zadara Storage Inc.
# Copyright (c) 2011 OpenStack Foundation
# Copyright 2011 University of Southern California
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

import ddt
import mock
import webob

from manila.api.contrib import types_extra_specs
from manila.common import constants
from manila import exception
from manila import test
from manila.tests.api import fakes
from manila.tests import fake_notifier
import manila.wsgi


def return_create_share_type_extra_specs(context, share_type_id, extra_specs):
    return stub_share_type_extra_specs()


def return_share_type_extra_specs(context, share_type_id):
    return stub_share_type_extra_specs()


def return_empty_share_type_extra_specs(context, share_type_id):
    return {}


def delete_share_type_extra_specs(context, share_type_id, key):
    pass


def delete_share_type_extra_specs_not_found(context, share_type_id, key):
    raise exception.ShareTypeExtraSpecsNotFound("Not Found")


def stub_share_type_extra_specs():
    specs = {"key1": "value1",
             "key2": "value2",
             "key3": "value3",
             "key4": "value4",
             "key5": "value5"}
    return specs


def share_type_get(context, share_type_id):
    pass


def get_large_string():
    return "s" * 256


def get_extra_specs_dict(extra_specs, include_required=True):

    if not extra_specs:
        extra_specs = {}

    if include_required:
        extra_specs[constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS] = False

    return {'extra_specs': extra_specs}


@ddt.ddt
class ShareTypesExtraSpecsTest(test.TestCase):

    def setUp(self):
        super(ShareTypesExtraSpecsTest, self).setUp()
        self.flags(host='fake')
        self.mock_object(manila.db, 'share_type_get', share_type_get)
        self.api_path = '/v2/fake/os-share-types/1/extra_specs'
        self.controller = types_extra_specs.ShareTypeExtraSpecsController()

        """to reset notifier drivers left over from other api/contrib tests"""
        fake_notifier.reset()
        self.addCleanup(fake_notifier.reset)

    def test_index(self):
        self.mock_object(manila.db, 'share_type_extra_specs_get',
                         return_share_type_extra_specs)

        req = fakes.HTTPRequest.blank(self.api_path)
        res_dict = self.controller.index(req, 1)

        self.assertEqual('value1', res_dict['extra_specs']['key1'])

    def test_index_no_data(self):
        self.mock_object(manila.db, 'share_type_extra_specs_get',
                         return_empty_share_type_extra_specs)

        req = fakes.HTTPRequest.blank(self.api_path)
        res_dict = self.controller.index(req, 1)

        self.assertEqual(0, len(res_dict['extra_specs']))

    def test_show(self):
        self.mock_object(manila.db, 'share_type_extra_specs_get',
                         return_share_type_extra_specs)

        req = fakes.HTTPRequest.blank(self.api_path + '/key5')
        res_dict = self.controller.show(req, 1, 'key5')

        self.assertEqual('value5', res_dict['key5'])

    def test_show_spec_not_found(self):
        self.mock_object(manila.db, 'share_type_extra_specs_get',
                         return_empty_share_type_extra_specs)

        req = fakes.HTTPRequest.blank(self.api_path + '/key6')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, 1, 'key6')

    def test_delete(self):
        self.mock_object(manila.db, 'share_type_extra_specs_delete',
                         delete_share_type_extra_specs)

        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path + '/key5')
        self.controller.delete(req, 1, 'key5')
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

    def test_delete_not_found(self):
        self.mock_object(manila.db, 'share_type_extra_specs_delete',
                         delete_share_type_extra_specs_not_found)

        req = fakes.HTTPRequest.blank(self.api_path + '/key6')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          req, 1, 'key6')

    def test_delete_forbidden(self):
        key = constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
        req = fakes.HTTPRequest.blank(self.api_path + '/' + key)

        self.assertRaises(webob.exc.HTTPForbidden, self.controller.delete,
                          req, 1, key)

    def test_create(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        body = get_extra_specs_dict({})

        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path)
        res_dict = self.controller.create(req, 1, body)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

        self.assertTrue(
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
            in res_dict['extra_specs'])

    def test_create_with_too_small_key(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        too_small_key = ""
        body = {"extra_specs": {too_small_key: "value"}}
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

    def test_create_with_too_big_key(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        too_big_key = "k" * 256
        body = {"extra_specs": {too_big_key: "value"}}
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

    def test_create_with_too_small_value(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        too_small_value = ""
        body = {"extra_specs": {"key": too_small_value}}
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

    def test_create_with_too_big_value(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        too_big_value = "v" * 256
        body = {"extra_specs": {"key": too_big_value}}
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path)
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

    @mock.patch.object(manila.db, 'share_type_extra_specs_update_or_create')
    def test_create_key_allowed_chars(
            self, share_type_extra_specs_update_or_create):
        mock_return_value = {"key1": "value1",
                             "key2": "value2",
                             "key3": "value3",
                             "key4": "value4",
                             "key5": "value5"}
        share_type_extra_specs_update_or_create.\
            return_value = mock_return_value

        body = get_extra_specs_dict({"other_alphanum.-_:": "value1"})

        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)

        req = fakes.HTTPRequest.blank(self.api_path)
        res_dict = self.controller.create(req, 1, body)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)
        self.assertEqual('value1',
                         res_dict['extra_specs']['other_alphanum.-_:'])

    @mock.patch.object(manila.db, 'share_type_extra_specs_update_or_create')
    def test_create_too_many_keys_allowed_chars(
            self, share_type_extra_specs_update_or_create):
        mock_return_value = {"key1": "value1",
                             "key2": "value2",
                             "key3": "value3",
                             "key4": "value4",
                             "key5": "value5"}
        share_type_extra_specs_update_or_create.\
            return_value = mock_return_value

        body = get_extra_specs_dict({
            "other_alphanum.-_:": "value1",
            "other2_alphanum.-_:": "value2",
            "other3_alphanum.-_:": "value3"
        })

        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)

        req = fakes.HTTPRequest.blank(self.api_path)
        res_dict = self.controller.create(req, 1, body)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)
        self.assertEqual('value1',
                         res_dict['extra_specs']['other_alphanum.-_:'])
        self.assertEqual('value2',
                         res_dict['extra_specs']['other2_alphanum.-_:'])
        self.assertEqual('value3',
                         res_dict['extra_specs']['other3_alphanum.-_:'])

    def test_update_item(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        key = constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
        body = {key: True}

        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 0)
        req = fakes.HTTPRequest.blank(self.api_path + '/' + key)
        res_dict = self.controller.update(req, 1, key, body)
        self.assertEqual(len(fake_notifier.NOTIFICATIONS), 1)

        self.assertEqual(True, res_dict[key])

    def test_update_item_too_many_keys(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        body = {"key1": "value1", "key2": "value2"}

        req = fakes.HTTPRequest.blank(self.api_path + '/key1')
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'key1', body)

    def test_update_item_body_uri_mismatch(self):
        self.mock_object(manila.db,
                         'share_type_extra_specs_update_or_create',
                         return_create_share_type_extra_specs)
        body = {"key1": "value1"}

        req = fakes.HTTPRequest.blank(self.api_path + '/bad')
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'bad', body)

    @ddt.data(None,
              {},
              {"extra_specs": {
                  constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: ""
              }})
    def test_update_invalid_body(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1/extra_specs')
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, '1', body)

    @ddt.data(None,
              {},
              {'foo': {'a': 'b'}},
              {'extra_specs': 'string'},
              {"extra_specs": {"ke/y1": "value1"}},
              {"key1": "value1", "ke/y2": "value2", "key3": "value3"},
              {"extra_specs": {
                  constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: ""}},
              {"extra_specs": {
                  constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: "111"}},
              {"extra_specs": {
                  constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS + "FAKE":
                      "fake"}},
              {"extra_specs": {"": "value"}},
              {"extra_specs": {"t": get_large_string()}},
              {"extra_specs": {get_large_string(): get_large_string()}},
              {"extra_specs": {get_large_string(): "v"}},
              {"extra_specs": {"k": ""}},
              )
    def test_create_invalid_body(self, body):
        req = fakes.HTTPRequest.blank('/v2/fake/types/1/extra_specs')
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, '1', body)
