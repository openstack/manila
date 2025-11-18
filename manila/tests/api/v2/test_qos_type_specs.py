# Copyright 2026 SAP SE.
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

from unittest import mock

import ddt
import webob

from manila.api.v2 import qos_type_specs
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
import manila.wsgi


def return_create_qos_type_specs(context, qos_type_id, specs):
    return stub_qos_type_specs()


def return_qos_type_specs(context, qos_type_id):
    return stub_qos_type_specs()


def return_empty_qos_type_specs(context, qos_type_id):
    return {}


def delete_qos_type_specs(context, qos_type_id, key):
    pass


def delete_qos_type_specs_not_found(context, qos_type_id, key):
    raise exception.QosTypeSpecsNotFound("Not Found")


def stub_qos_type_specs():
    specs = {"key1": "value1",
             "key2": "value2",
             "key3": "value3",
             "key4": "value4",
             "key5": "value5"}
    return specs


def qos_type_get(context, id, inactive=False, expected_fields=None):
    pass


def get_large_string():
    return "s" * 256


def get_specs_dict(specs):

    if not specs:
        specs = {}

    return {'specs': specs}


@ddt.ddt
class QosTypeSpecsTest(test.TestCase):

    def setUp(self):
        super(QosTypeSpecsTest, self).setUp()
        self.flags(host='fake')
        self.mock_object(manila.db, 'qos_type_get', qos_type_get)
        self.api_path = '/v2/fake/qos-types/1/specs'
        self.controller = (
            qos_type_specs.QosTypeSpecsController())
        self.resource_name = self.controller.resource_name
        self.api_version = qos_type_specs.MIN_SUPPORTED_API_VERSION
        self.mock_policy_check = self.mock_object(policy, 'check_policy')

    def test_index(self):
        self.mock_object(manila.db, 'qos_type_specs_get',
                         return_qos_type_specs)

        req = fakes.HTTPRequest.blank(
            self.api_path,
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req, 1)

        self.assertEqual('value1', res_dict['specs']['key1'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_index_no_data(self):
        self.mock_object(manila.db, 'qos_type_specs_get',
                         return_empty_qos_type_specs)

        req = fakes.HTTPRequest.blank(
            self.api_path,
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req, 1)

        self.assertEqual(0, len(res_dict['specs']))
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'index')

    def test_show(self):
        self.mock_object(manila.db, 'qos_type_specs_get',
                         return_qos_type_specs)

        req = fakes.HTTPRequest.blank(
            self.api_path + '/key5',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        res_dict = self.controller.show(req, 1, 'key5')

        self.assertEqual('value5', res_dict['key5'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'show')

    def test_show_spec_not_found(self):
        self.mock_object(manila.db, 'qos_type_specs_get',
                         return_empty_qos_type_specs)

        req = fakes.HTTPRequest.blank(
            self.api_path + '/key6',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, 1, 'key6')
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'show')

    def test_delete(self):
        self.mock_object(manila.db, 'qos_type_specs_delete',
                         delete_qos_type_specs)

        req = fakes.HTTPRequest.blank(
            self.api_path + '/key5',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.controller.delete(req, 1, 'key5')
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'delete')

    def test_delete_not_found(self):
        self.mock_object(manila.db, 'qos_type_specs_delete',
                         delete_qos_type_specs_not_found)

        req = fakes.HTTPRequest.blank(
            self.api_path + '/key6',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          req, 1, 'key6')
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'delete')

    def test_create(self):
        data = {'k1': 'v1', 'k2': 'v2', 'k3': 'v3'}
        body = {'specs': data}
        self.mock_object(
            manila.db, 'qos_type_specs_update_or_create',
            mock.Mock(return_value=return_create_qos_type_specs))
        req = fakes.HTTPRequest.blank(
            self.api_path,
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        res_dict = self.controller.create(req, 1, body)

        for k, v in data.items():
            self.assertIn(k, res_dict['specs'])
            self.assertEqual(v, res_dict['specs'][k])
        (manila.db.qos_type_specs_update_or_create.
            assert_called_once_with(
                req.environ['manila.context'], 1, body['specs']))
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    @ddt.data(
        {"": "value"},
        {"k" * 256: "value"},
        {"key": ""},
        {"key": "v" * 256},
    )
    def test_create_with_invalid_specs(self, specs):
        self.mock_object(
            manila.db, 'qos_type_specs_update_or_create',
            mock.Mock(return_value=return_create_qos_type_specs))
        body = {"specs": specs}
        req = fakes.HTTPRequest.blank(
            self.api_path,
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, 1, body)

        self.assertFalse(
            manila.db.qos_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')

    def test_update_item(self):
        self.mock_object(
            manila.db, 'qos_type_specs_update_or_create',
            mock.Mock(return_value=return_create_qos_type_specs))
        req = fakes.HTTPRequest.blank(
            self.api_path + '/key2',
            version=self.api_version,
            use_admin_context=True
        )
        body = {'key2': 'new_value2'}
        req_context = req.environ['manila.context']

        res_dict = self.controller.update(
            req, 1, 'key2', body)

        self.assertEqual(res_dict['key2'], 'new_value2')
        (manila.db.qos_type_specs_update_or_create.
            assert_called_once_with(req_context, 1, body))
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    def test_update_item_too_many_keys(self):
        self.mock_object(manila.db, 'qos_type_specs_update_or_create')
        body = {"key1": "value1", "key2": "value2"}
        req = fakes.HTTPRequest.blank(
            self.api_path + '/key1',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'key1', body)

        self.assertFalse(
            manila.db.qos_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    def test_update_item_body_uri_mismatch(self):
        self.mock_object(manila.db, 'qos_type_specs_update_or_create')
        body = {"key1": "value1"}
        req = fakes.HTTPRequest.blank(
            self.api_path + '/bad',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']

        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          req, 1, 'bad', body)

        self.assertFalse(
            manila.db.qos_type_specs_update_or_create.called)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    @ddt.data(None, {}, {"specs": {'key1': ""}})
    def test_update_invalid_body(self, body):
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/1/specs',
            version=self.api_version,
        )
        req_context = req.environ['manila.context']
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update, req, '1', body)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'update')

    @ddt.data(
        None, {}, {'foo': {'a': 'b'}}, {'specs': 'string'},
        {"specs": {"ke/y1": "value1"}},
        {"key1": "value1", "ke/y2": "value2", "key3": "value3"},
        {"specs": {"": "value"}},
        {"specs": {"t": get_large_string()}},
        {"specs": {get_large_string(): get_large_string()}},
        {"specs": {get_large_string(): "v"}},
        {"specs": {"k": ""}})
    def test_create_invalid_body(self, body):
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/1/specs',
            version=self.api_version,
            use_admin_context=True
        )
        req_context = req.environ['manila.context']
        req.method = 'POST'

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, '1', body)
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'create')
