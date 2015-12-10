# Copyright 2015 Mirantis inc.
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
from oslo_utils import uuidutils

from manila.share import drivers_private_data as pd
from manila import test


@ddt.ddt
class DriverPrivateDataTestCase(test.TestCase):
    """Tests DriverPrivateData."""

    def setUp(self):
        super(DriverPrivateDataTestCase, self).setUp()

        self.fake_storage = mock.Mock()
        self.entity_id = uuidutils.generate_uuid()

    def test_default_storage_driver(self):
        private_data = pd.DriverPrivateData(
            storage=None, context="fake", backend_host="fake")

        self.assertIsInstance(private_data._storage, pd.SqlStorageDriver)

    def test_custom_storage_driver(self):
        private_data = pd.DriverPrivateData(storage=self.fake_storage)

        self.assertEqual(self.fake_storage, private_data._storage)

    def test_invalid_parameters(self):
        self.assertRaises(ValueError, pd.DriverPrivateData)

    @ddt.data({'context': 'fake'}, {'backend_host': 'fake'})
    def test_invalid_single_parameter(self, test_args):
        self.assertRaises(ValueError, pd.DriverPrivateData, **test_args)

    @ddt.data("111", ["fake"], None)
    def test_validate_entity_id_invalid(self, entity_id):
        data = pd.DriverPrivateData(storage="fake")

        self.assertRaises(ValueError, data._validate_entity_id, entity_id)

    def test_validate_entity_id_valid(self):
        actual_result = (
            pd.DriverPrivateData._validate_entity_id(self.entity_id)
        )

        self.assertIsNone(actual_result)

    def test_update(self):
        data = pd.DriverPrivateData(storage=self.fake_storage)
        details = {"foo": "bar"}
        self.mock_object(self.fake_storage, 'update',
                         mock.Mock(return_value=True))

        actual_result = data.update(
            self.entity_id,
            details,
            delete_existing=True
        )

        self.assertTrue(actual_result)
        self.fake_storage.update.assert_called_once_with(
            self.entity_id, details, True
        )

    def test_update_invalid(self):
        data = pd.DriverPrivateData(storage=self.fake_storage)
        details = ["invalid"]
        self.mock_object(self.fake_storage, 'update',
                         mock.Mock(return_value=True))

        self.assertRaises(
            ValueError, data.update, self.entity_id, details)

        self.assertFalse(self.fake_storage.update.called)

    def test_get(self):
        data = pd.DriverPrivateData(storage=self.fake_storage)
        key = "fake_key"
        value = "fake_value"
        default_value = "def"
        self.mock_object(self.fake_storage, 'get',
                         mock.Mock(return_value=value))

        actual_result = data.get(self.entity_id, key, default_value)

        self.assertEqual(value, actual_result)
        self.fake_storage.get.assert_called_once_with(
            self.entity_id, key, default_value
        )

    def test_delete(self):
        data = pd.DriverPrivateData(storage=self.fake_storage)
        key = "fake_key"
        self.mock_object(self.fake_storage, 'get',
                         mock.Mock(return_value=True))

        actual_result = data.delete(self.entity_id, key)

        self.assertTrue(actual_result)
        self.fake_storage.delete.assert_called_once_with(
            self.entity_id, key
        )


fake_storage_data = {
    "entity_id": "fake_id",
    "details": {"foo": "bar"},
    "context": "fake_context",
    "backend_host": "fake_host",
    "default": "def",
    "delete_existing": True,
    "key": "fake_key",
}


def create_arg_list(key_names):
    return [fake_storage_data[key] for key in key_names]


def create_arg_dict(key_names):
    return {key: fake_storage_data[key] for key in key_names}


@ddt.ddt
class SqlStorageDriverTestCase(test.TestCase):

    @ddt.data(
        {
            "method_name": 'update',
            "method_kwargs": create_arg_dict(
                ["entity_id", "details", "delete_existing"]),
            "valid_args": create_arg_list(
                ["context", "backend_host", "entity_id", "details",
                 "delete_existing"]
            )
        },
        {
            "method_name": 'get',
            "method_kwargs": create_arg_dict(["entity_id", "key", "default"]),
            "valid_args": create_arg_list(
                ["context", "backend_host", "entity_id", "key", "default"]),
        },
        {
            "method_name": 'delete',
            "method_kwargs": create_arg_dict(["entity_id", "key"]),
            "valid_args": create_arg_list(
                ["context", "backend_host", "entity_id", "key"]),
        })
    @ddt.unpack
    def test_methods(self, method_kwargs, method_name, valid_args):
        method = method_name
        db_method = 'driver_private_data_' + method_name

        with mock.patch('manila.db.api.' + db_method) as db_method:
            storage_driver = pd.SqlStorageDriver(
                context=fake_storage_data['context'],
                backend_host=fake_storage_data['backend_host'])
            method = getattr(storage_driver, method)

            method(**method_kwargs)

            db_method.assert_called_once_with(*valid_args)
