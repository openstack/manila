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
from oslo_utils import strutils
import webob

from manila.api.v2 import share_group_type_specs
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
import manila.wsgi

CONSISTENT_SNAPSHOTS = 'consistent_snapshots'


def return_create_share_group_type_specs(context, share_group_type_id,
                                         group_specs):
    return stub_share_group_type_specs()


def return_share_group_type_specs(context, share_group_type_id):
    return stub_share_group_type_specs()


def return_empty_share_group_type_specs(context, share_group_type_id):
    return {}


def delete_share_group_type_specs(context, share_group_type_id, key):
    pass


def delete_share_group_type_specs_not_found(context, share_group_type_id, key):
    raise exception.ShareGroupTypeSpecsNotFound("Not Found")


def stub_share_group_type_specs():
    return {"key%d" % i: "value%d" % i for i in (1, 2, 3, 4, 5)}


def get_large_string():
    return "s" * 256


def get_group_specs_dict(group_specs, include_required=True):

    if not group_specs:
        group_specs = {}

    return {'group_specs': group_specs}


def fake_request(url, admin=False, experimental=True, version='2.31',
                 **kwargs):
    return fakes.HTTPRequest.blank(
        url, use_admin_context=admin, experimental=experimental,
        version=version, **kwargs)


@ddt.ddt
class ShareGroupTypesSpecsTest(test.TestCase):

    def setUp(self):
        super(ShareGroupTypesSpecsTest, self).setUp()
        self.flags(host='fake')
        self.mock_object(manila.db, 'share_group_type_get')
        self.api_path = '/v2/fake/share-group-types/1/group_specs'
        self.controller = (
            share_group_type_specs.ShareGroupTypeSpecsController())
        self.resource_name = self.controller.resource_name
        self.mock_policy_check = self.mock_object(policy, 'check_policy')

    def test_index(self):
        self.mock_object(
            manila.db, 'share_group_type_specs_get',
            return_share_group_type_specs)
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req, 1)

        self.assertEqual('value1', res_dict['group_specs']['key1'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_index_no_data(self):
        self.mock_object(manila.db, 'share_group_type_specs_get',
                         return_empty_share_group_type_specs)
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req, 1)

        self.assertEqual(0, len(res_dict['group_specs']))
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_show(self):
        self.mock_object(manila.db, 'share_group_type_specs_get',
                         return_share_group_type_specs)
        req = fake_request(self.api_path + '/key5')
        req_context = req.environ['manila.context']

        res_dict = self.controller.show(req, 1, 'key5')

        self.assertEqual('value5', res_dict['key5'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'show')

    def test_show_spec_not_found(self):
        self.mock_object(manila.db, 'share_group_type_specs_get',
                         return_empty_share_group_type_specs)
        req = fake_request(self.api_path + '/key6')
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, 1, 'key6')

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'show')

    def test_delete(self):
        self.mock_object(manila.db, 'share_group_type_specs_delete',
                         delete_share_group_type_specs)
        req = fake_request(self.api_path + '/key5')
        req_context = req.environ['manila.context']

        self.controller.delete(req, 1, 'key5')

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'delete')

    def test_delete_not_found(self):
        self.mock_object(manila.db, 'share_group_type_specs_delete',
                         delete_share_group_type_specs_not_found)
        req = fake_request(self.api_path + '/key6')
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          req, 1, 'key6')

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'delete')

    @ddt.data(
        get_group_specs_dict({}),
        {'foo': 'bar'},
        {CONSISTENT_SNAPSHOTS + 'foo': True},
        {'foo' + CONSISTENT_SNAPSHOTS: False},
        *[{CONSISTENT_SNAPSHOTS: v}
          for v in strutils.TRUE_STRINGS + strutils.FALSE_STRINGS]
    )
    def test_create(self, data):
        body = {'group_specs': data}
        mock_spec_update_or_create = self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=return_create_share_group_type_specs))
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        res_dict = self.controller.create(req, 1, body)

        for k, v in data.items():
            self.assertIn(k, res_dict['group_specs'])
            self.assertEqual(v, res_dict['group_specs'][k])
        mock_spec_update_or_create.assert_called_once_with(
            req.environ['manila.context'], 1, body['group_specs'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_create_with_too_small_key(self):
        self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=return_create_share_group_type_specs))
        too_small_key = ""
        body = {"group_specs": {too_small_key: "value"}}
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_create_with_too_big_key(self):
        self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=return_create_share_group_type_specs))
        too_big_key = "k" * 256
        body = {"group_specs": {too_big_key: "value"}}
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_create_with_too_small_value(self):
        self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=return_create_share_group_type_specs))
        too_small_value = ""
        body = {"group_specs": {"key": too_small_value}}
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')
        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)

    def test_create_with_too_big_value(self):
        self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=return_create_share_group_type_specs))
        too_big_value = "v" * 256
        body = {"extra_specs": {"key": too_big_value}}
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')
        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)

    def test_create_key_allowed_chars(self):
        mock_return_value = stub_share_group_type_specs()
        mock_spec_update_or_create = self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=mock_return_value))
        body = get_group_specs_dict({"other_alphanum.-_:": "value1"})
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        res_dict = self.controller.create(req, 1, body)

        self.assertEqual(mock_return_value['key1'],
                         res_dict['group_specs']['other_alphanum.-_:'])
        mock_spec_update_or_create.assert_called_once_with(
            req.environ['manila.context'], 1, body['group_specs'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_create_too_many_keys_allowed_chars(self):
        mock_return_value = stub_share_group_type_specs()
        mock_spec_update_or_create = self.mock_object(
            manila.db, 'share_group_type_specs_update_or_create',
            mock.Mock(return_value=mock_return_value))
        body = get_group_specs_dict({
            "other_alphanum.-_:": "value1",
            "other2_alphanum.-_:": "value2",
            "other3_alphanum.-_:": "value3",
        })
        req = fake_request(self.api_path)
        req_context = req.environ['manila.context']

        res_dict = self.controller.create(req, 1, body)

        self.assertEqual(mock_return_value['key1'],
                         res_dict['group_specs']['other_alphanum.-_:'])
        self.assertEqual(mock_return_value['key2'],
                         res_dict['group_specs']['other2_alphanum.-_:'])
        self.assertEqual(mock_return_value['key3'],
                         res_dict['group_specs']['other3_alphanum.-_:'])
        mock_spec_update_or_create.assert_called_once_with(
            req_context, 1, body['group_specs'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_update_item_too_many_keys(self):
        self.mock_object(manila.db, 'share_group_type_specs_update_or_create')
        body = {"key1": "value1", "key2": "value2"}
        req = fake_request(self.api_path + '/key1')
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'key1', body)

        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    def test_update_item_body_uri_mismatch(self):
        self.mock_object(manila.db, 'share_group_type_specs_update_or_create')
        body = {"key1": "value1"}
        req = fake_request(self.api_path + '/bad')
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'bad', body)

        self.assertFalse(
            manila.db.share_group_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    @ddt.data(None, {}, {"group_specs": {CONSISTENT_SNAPSHOTS: ""}})
    def test_update_invalid_body(self, body):
        req = fake_request('/v2/fake/share-group-types/1/group_specs')
        req_context = req.environ['manila.context']
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, '1', body)

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    @ddt.data(
        None, {}, {'foo': {'a': 'b'}}, {'group_specs': 'string'},
        {"group_specs": {"ke/y1": "value1"}},
        {"key1": "value1", "ke/y2": "value2", "key3": "value3"},
        {"group_specs": {CONSISTENT_SNAPSHOTS: ""}},
        {"group_specs": {"": "value"}},
        {"group_specs": {"t": get_large_string()}},
        {"group_specs": {get_large_string(): get_large_string()}},
        {"group_specs": {get_large_string(): "v"}},
        {"group_specs": {"k": ""}})
    def test_create_invalid_body(self, body):
        req = fake_request('/v2/fake/share-group-types/1/group_specs')
        req_context = req.environ['manila.context']
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, '1', body)

        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')
