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

import ddt
import mock
from oslo_utils import timeutils
import webob

from manila.api.v1 import share_types as types
from manila.api.views import types as views_types
from manila.common import constants
from manila import exception
from manila import policy
from manila.share import share_types
from manila import test
from manila.tests.api import fakes


def stub_share_type(id):
    specs = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
        "key4": "value4",
        "key5": "value5",
        constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: "true",
    }
    return dict(
        id=id,
        name='share_type_%s' % str(id),
        extra_specs=specs,
        required_extra_specs={
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: "true",
        }
    )


def return_share_types_get_all_types(context, search_opts=None):
    return dict(
        share_type_1=stub_share_type(1),
        share_type_2=stub_share_type(2),
        share_type_3=stub_share_type(3)
    )


def return_empty_share_types_get_all_types(context, search_opts=None):
    return {}


def return_share_types_get_share_type(context, id=1):
    if id == "777":
        raise exception.ShareTypeNotFound(share_type_id=id)
    return stub_share_type(int(id))


def return_share_types_get_by_name(context, name):
    if name == "777":
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    return stub_share_type(int(name.split("_")[2]))


@ddt.ddt
class ShareTypesApiTest(test.TestCase):
    def setUp(self):
        super(ShareTypesApiTest, self).setUp()
        self.controller = types.ShareTypesController()
        self.mock_object(policy, 'check_policy',
                         mock.Mock(return_value=True))

    @ddt.data(True, False)
    def test_share_types_index(self, admin):
        self.mock_object(share_types, 'get_all_types',
                         return_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types',
                                      use_admin_context=admin)

        res_dict = self.controller.index(req)

        self.assertEqual(3, len(res_dict['share_types']))

        expected_names = ['share_type_1', 'share_type_2', 'share_type_3']
        actual_names = map(lambda e: e['name'], res_dict['share_types'])
        self.assertEqual(set(expected_names), set(actual_names))
        for entry in res_dict['share_types']:
            if admin:
                self.assertEqual('value1', entry['extra_specs'].get('key1'))
            else:
                self.assertIsNone(entry['extra_specs'].get('key1'))
            self.assertTrue('required_extra_specs' in entry)
            required_extra_spec = entry['required_extra_specs'].get(
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS, '')
            self.assertEqual('true', required_extra_spec)
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'index')

    def test_share_types_index_no_data(self):
        self.mock_object(share_types, 'get_all_types',
                         return_empty_share_types_get_all_types)

        req = fakes.HTTPRequest.blank('/v2/fake/types')
        res_dict = self.controller.index(req)

        self.assertEqual(0, len(res_dict['share_types']))
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'index')

    def test_share_types_show(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/1')
        res_dict = self.controller.show(req, 1)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'show')

    def test_share_types_show_not_found(self):
        self.mock_object(share_types, 'get_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/777')
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, '777')
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'show')

    def test_share_types_default(self):
        self.mock_object(share_types, 'get_default_share_type',
                         return_share_types_get_share_type)

        req = fakes.HTTPRequest.blank('/v2/fake/types/default')
        res_dict = self.controller.default(req)

        self.assertEqual(2, len(res_dict))
        self.assertEqual('1', res_dict['share_type']['id'])
        self.assertEqual('share_type_1', res_dict['share_type']['name'])
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'default')

    def test_share_types_default_not_found(self):
        self.mock_object(share_types, 'get_default_share_type',
                         mock.Mock(side_effect=exception.ShareTypeNotFound(
                             share_type_id="fake")))
        req = fakes.HTTPRequest.blank('/v2/fake/types/default')

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.default, req)
        policy.check_policy.assert_called_once_with(
            req.environ['manila.context'], types.RESOURCE_NAME, 'default')

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
            required_extra_specs={},
            id=42,
        )

        request = fakes.HTTPRequest.blank("/v2")
        output = view_builder.show(request, raw_share_type)

        self.assertIn('share_type', output)
        expected_share_type = dict(
            name='new_type',
            extra_specs={},
            required_extra_specs={},
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
                    required_extra_specs={},
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
                required_extra_specs={},
                id=42 + i
            )
            self.assertDictMatch(output['share_types'][i],
                                 expected_share_type)

    @ddt.data(None, True, 'true', 'false', 'all')
    def test_parse_is_public_valid(self, value):
        result = self.controller._parse_is_public(value)
        self.assertTrue(result in (True, False, None))

    def test_parse_is_public_invalid(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller._parse_is_public,
                          'fakefakefake')
