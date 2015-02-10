# Copyright 2011 OpenStack Foundation
# aLL Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from oslo_utils import timeutils
import webob

from manila.api.v1 import share_types as types
from manila.api.views import types as views_types
from manila import exception
from manila.share import share_types
from manila import test
from manila.tests.api import fakes


def stub_share_type(id):
    specs = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
        "key4": "value4",
        "key5": "value5"
    }
    return dict(
        id=id,
        name='share_type_%s' % str(id),
        extra_specs=specs,
    )


def return_share_types_get_all_types(context):
    return dict(
        share_type_1=stub_share_type(1),
        share_type_2=stub_share_type(2),
        share_type_3=stub_share_type(3)
    )


def return_empty_share_types_get_all_types(context):
    return {}


def return_share_types_get_share_type(context, id=1):
    if id == "777":
        raise exception.ShareTypeNotFound(share_type_id=id)
    return stub_share_type(int(id))


def return_share_types_get_by_name(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    return stub_share_type(int(name.split("_")[2]))


class ShareTypesApiTest(test.TestCase):
    def setUp(self):
        super(ShareTypesApiTest, self).setUp()
        self.controller = types.ShareTypesController()

    def test_share_types_index(self):
        self.mock_object(share_types, 'get_all_types',
                         return_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types')
        res_dict = self.controller.index(req)

        self.assertEqual(3, len(res_dict['share_types']))

        expected_names = ['share_type_1', 'share_type_2', 'share_type_3']
        actual_names = map(lambda e: e['name'], res_dict['share_types'])
        self.assertEqual(set(actual_names), set(expected_names))
        for entry in res_dict['share_types']:
            self.assertEqual('value1', entry['extra_specs']['key1'])

    def test_share_types_index_no_data(self):
        self.mock_object(share_types, 'get_all_types',
                         return_empty_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types')
        res_dict = self.controller.index(req)

        self.assertEqual(0, len(res_dict['share_types']))

    def test_share_types_show(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        res_dict = self.controller.show(req, 1)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])

    def test_share_types_show_not_found(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, '777')

    def test_share_types_default(self):
        self.mock_object(share_types, 'get_default_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/default')
        res_dict = self.controller.default(req)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])

    def test_share_types_default_not_found(self):
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(side_effect=exception.ShareTypeNotFound(
                             share_type_id="fake")))
        req = fakes.HTTPRequest.blank('/v2/fake/types/default')

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.default, req)

    def test_view_builder_show(self):
        view_builder = views_types.ViewBuilder()

        now = timeutils.isotime()
        raw_share_type = dict(
            name='new_type',
            deleted=False,
            created_at=now,
            updated_at=now,
            extra_specs={},
            deleted_at=None,
            id=42,
        )

        request = fakes.HTTPRequest.blank("/v2")
        output = view_builder.show(request, raw_share_type)

        self.assertIn('share_type', output)
        expected_share_type = dict(
            name='new_type',
            extra_specs={},
            id=42,
        )
        self.assertDictMatch(output['share_type'], expected_share_type)

    def test_view_builder_list(self):
        view_builder = views_types.ViewBuilder()

        now = timeutils.isotime()
        raw_share_types = []
        for i in range(0, 10):
            raw_share_types.append(
                dict(
                    name='new_type',
                    deleted=False,
                    created_at=now,
                    updated_at=now,
                    extra_specs={},
                    deleted_at=None,
                    id=42 + i
                )
            )

        request = fakes.HTTPRequest.blank("/v2")
        output = view_builder.index(request, raw_share_types)

        self.assertIn('share_types', output)
        for i in range(0, 10):
            expected_share_type = dict(
                name='new_type',
                extra_specs={},
                id=42 + i
            )
            self.assertDictMatch(output['share_types'][i],
                                 expected_share_type)
