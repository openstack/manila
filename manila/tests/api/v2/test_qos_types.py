# Copyright 2026 SAP SE.
# All Rights Reserved.
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

import copy
from unittest import mock

import ddt
from oslo_config import cfg
import webob

from manila.api.v2 import qos_types
from manila.db import api as db_api
from manila import exception
from manila import policy
from manila.share import api as share_api
from manila import test
from manila.tests.api import fakes

CONF = cfg.CONF


def stub_qos_type(id):
    specs = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
        "key4": "value4",
        "key5": "value5",
    }
    if id == 4:
        name = 'update_qos_type_%s' % str(id)
        description = 'update_description_%s' % str(id)
    else:
        name = 'qos_type_%s' % str(id)
        description = 'description_%s' % str(id)
    qos_type = {
        'id': str(id),
        'name': name,
        'description': description,
        'specs': specs,
    }
    return qos_type


def return_qos_types_get_all(context, filters=None, limit=None, offset=None,
                             sort_key=None, sort_dir=None):
    return {
        "1": stub_qos_type(1),
        "2": stub_qos_type(2),
        "3": stub_qos_type(3)
    }


def return_empty_qos_types_get_all(context, filters=None,
                                   limit=None, offset=None,
                                   sort_key=None, sort_dir=None):
    return {}


def make_create_body(name="test_qos_1", specs=None, description=None):
    if not specs:
        specs = {}

    body = {
        "qos_type": {
            "name": name,
            "description": description,
            "specs": specs,
        }
    }

    return body


def make_update_body(name=None, description=None):
    body = {"qos_type": {}}
    if name:
        body["qos_type"].update({"name": name})
    if description:
        body["qos_type"].update({"description": description})

    return body


@ddt.ddt
class QosTypesAPITest(test.TestCase):

    def setUp(self):
        super(QosTypesAPITest, self).setUp()
        self.controller = qos_types.QosTypesController()
        self.resource_name = self.controller.resource_name
        self.api_version = qos_types.MIN_SUPPORTED_API_VERSION
        self.req = fakes.HTTPRequest.blank(
            '/qos-types',
            version=self.api_version,
        )
        self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True)
        )

    def test_qos_types_index(self):
        self.mock_object(db_api, 'qos_type_get_all',
                         return_qos_types_get_all)

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
        )

        res_dict = self.controller.index(req)

        self.assertEqual(3, len(res_dict['qos_types']))

        expected_names = ['qos_type_1', 'qos_type_2', 'qos_type_3']
        actual_names = map(lambda e: e['name'], res_dict['qos_types'])
        self.assertEqual(set(expected_names), set(actual_names))
        for entry in res_dict['qos_types']:
            self.assertEqual('value1', entry['specs'].get('key1'))

    def test_qos_types_index_no_data(self):
        self.mock_object(db_api, 'qos_type_get_all',
                         return_empty_qos_types_get_all)

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
        )
        res_dict = self.controller.index(req)

        self.assertEqual(0, len(res_dict['qos_types']))

    def test_qos_types_show(self):
        self.mock_object(db_api, 'qos_type_get',
                         mock.Mock(return_value=stub_qos_type(1)))

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/1',
            version=self.api_version,
        )
        res_dict = self.controller.show(req, 1)

        self.assertEqual(1, len(res_dict))
        self.assertEqual('1', res_dict['qos_type']['id'])
        self.assertEqual('qos_type_1', res_dict['qos_type']['name'])
        self.assertEqual('value1', res_dict['qos_type']['specs']['key1'])

    def test_qos_types_show_not_found(self):
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(
                side_effect=exception.QosTypeNotFound(qos_type_id='777')))

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/777',
            version=self.api_version,
        )
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.show,
                          req, '777')

    @ddt.data(
        (make_create_body("qos_type_1")),
        (make_create_body(specs={'key': 'val'}, description="description_1")),
        (make_create_body(specs={'key': 'val'})),
    )
    def test_create(self, body):
        self.mock_object(
            db_api, 'qos_type_get_by_name',
            mock.Mock(
                side_effect=exception.QosTypeNotFoundByName(
                    qos_type_name='fake')))

        self.mock_object(
            share_api.API, 'create_qos_type',
            mock.Mock(return_value=stub_qos_type(1))
        )
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
            use_admin_context=True
        )

        res_dict = self.controller.create(req, body)

        self.assertEqual(1, len(res_dict))
        self.assertEqual('qos_type_1', res_dict['qos_type']['name'])
        share_api.API.create_qos_type.assert_called_once_with(
            mock.ANY,
            body['qos_type']
        )

    def test_create_already_exists(self):
        self.mock_object(
            db_api, 'qos_type_get_by_name',
            mock.Mock(return_value='fake_qos_type')
        )
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
        )

        body = make_create_body('qos_type_1')
        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.create, req, body)

    def test_create_already_exists_race_condition(self):
        self.mock_object(
            db_api, 'qos_type_get_by_name',
            mock.Mock(
                side_effect=exception.QosTypeNotFoundByName(
                    qos_type_name='qos_type_1')))

        self.mock_object(
            self.controller.share_api,
            'create_qos_type',
            mock.Mock(
                side_effect=exception.QosTypeExists(id='qos_type_1'))
        )

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
        )

        body = make_create_body('qos_type_1')
        self.assertRaises(
            webob.exc.HTTPConflict,
            self.controller.create, req, body)

    def test_create_missing_qos_type_name(self):
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types',
            version=self.api_version,
        )

        body = dict(qos_type={'description': 'fake'})
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create, req, body)

    def test_qos_types_update(self):
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(return_value=stub_qos_type(4)))

        body = make_update_body("update_qos_type_4_1",
                                "update_description_4_1")
        qos_update_response = copy.deepcopy(stub_qos_type(4))
        qos_update_response['description'] = "update_description_4_1"
        self.mock_object(
            share_api.API, 'update_qos_type',
            mock.Mock(return_value=qos_update_response)
        )
        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/4',
            version=self.api_version,
            use_admin_context=True
        )
        res_dict = self.controller.update(req, 4, body)

        self.assertEqual(1, len(res_dict))
        self.assertEqual('update_description_4_1',
                         res_dict['qos_type']['description'])

    def test_qos_types_update_not_found(self):
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(
                side_effect=exception.QosTypeNotFound(qos_type_id='777')))

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/777',
            version=self.api_version,
        )

        body = make_update_body("update_qos_type_999",
                                "update_description_999")
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.update,
                          req, '777', body)

    def test_qos_types_delete(self):
        qos_type_obj = mock.Mock()
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(return_value=qos_type_obj))
        self.mock_object(share_api.API, 'delete_qos_type')

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/1',
            version=self.api_version,
        )
        self.controller.delete(req, 1)

        share_api.API.delete_qos_type.assert_called_once_with(
            mock.ANY,
            qos_type_obj
        )

    def test_qos_types_delete_not_found(self):
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(
                side_effect=exception.QosTypeNotFound(qos_type_id='777')))
        self.mock_object(share_api.API, 'delete_qos_type')

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/777',
            version=self.api_version,
        )
        self.assertRaises(webob.exc.HTTPNotFound, self.controller.delete,
                          req, '777')

    def test_qos_types_delete_in_use(self):
        qos_type_obj = mock.Mock()
        self.mock_object(
            db_api, 'qos_type_get',
            mock.Mock(return_value=qos_type_obj)
        )
        self.mock_object(
            share_api.API, 'delete_qos_type',
            mock.Mock(side_effect=exception.QosTypeInUse(qos_type_id='1'))
        )

        req = fakes.HTTPRequest.blank(
            '/v2/qos-types/1',
            version=self.api_version,
        )
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.delete,
                          req, '1')
