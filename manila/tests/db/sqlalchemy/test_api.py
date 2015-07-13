# Copyright (c) 2015 Rushil Chugh
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

"""Testing of SQLAlchemy backend."""

import ddt
from oslo_utils import uuidutils
import six

from manila import context
from manila.db.sqlalchemy import api
from manila import exception
from manila import test


@ddt.ddt
class SQLAlchemyAPIShareTestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(SQLAlchemyAPIShareTestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    @ddt.unpack
    @ddt.data(
        {'values': {'test': 'fake'}, 'call_count': 1},
        {'values': {'test': 'fake', 'id': 'fake'}, 'call_count': 0},
        {'values': {'test': 'fake', 'fooid': 'fake'}, 'call_count': 1},
        {'values': {'test': 'fake', 'idfoo': 'fake'}, 'call_count': 1},
    )
    def test_ensure_model_values_has_id(self, values, call_count):
        self.mock_object(uuidutils, 'generate_uuid')

        api.ensure_model_dict_has_id(values)

        self.assertEqual(call_count, uuidutils.generate_uuid.call_count)
        self.assertIn('id', values)

    def test_share_filter_by_host_with_pools(self):
        shares = [[api.share_create(self.ctxt, {'host': value})
                   for value in ('foo', 'foo#pool0')]]

        api.share_create(self.ctxt, {'host': 'foobar'})
        self._assertEqualListsOfObjects(shares[0],
                                        api.share_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])

    def test_share_filter_all_by_host_with_pools_multiple_hosts(self):
        shares = [[api.share_create(self.ctxt, {'host': value})
                   for value in ('foo', 'foo#pool0', 'foo', 'foo#pool1')]]

        api.share_create(self.ctxt, {'host': 'foobar'})
        self._assertEqualListsOfObjects(shares[0],
                                        api.share_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])

    def test_share_export_locations_update_valid_order(self):
        share = api.share_create(self.ctxt, {'host': 'foobar'})
        initial_locations = ['fake1/1/', 'fake2/2', 'fake3/3']
        update_locations = ['fake4/4', 'fake2/2', 'fake3/3']

        # add initial locations
        api.share_export_locations_update(self.ctxt, share['id'],
                                          initial_locations, False)
        # update locations
        api.share_export_locations_update(self.ctxt, share['id'],
                                          update_locations, True)
        actual_result = api.share_export_locations_get(self.ctxt, share['id'])

        # actual result should contain locations in exact same order
        self.assertTrue(actual_result == update_locations)

    def test_share_export_locations_update_string(self):
        share = api.share_create(self.ctxt, {'host': 'foobar'})
        initial_location = 'fake1/1/'

        api.share_export_locations_update(self.ctxt, share['id'],
                                          initial_location, False)
        actual_result = api.share_export_locations_get(self.ctxt, share['id'])

        self.assertTrue(actual_result == [initial_location])

    def _get_driver_test_data(self):
        return ("fake@host", uuidutils.generate_uuid())

    @ddt.data({"details": {"foo": "bar", "tee": "too"},
               "valid": {"foo": "bar", "tee": "too"}},
              {"details": {"foo": "bar", "tee": ["test"]},
               "valid": {"foo": "bar", "tee": six.text_type(["test"])}})
    @ddt.unpack
    def test_driver_private_data_update(self, details, valid):
        test_host, test_id = self._get_driver_test_data()

        initial_data = api.driver_private_data_get(
            self.ctxt, test_host, test_id)
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)
        actual_data = api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual({}, initial_data)
        self.assertEqual(valid, actual_data)

    def test_driver_private_data_update_with_duplicate(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"tee": "too"}

        api.driver_private_data_update(self.ctxt, test_host, test_id, details)
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)

        actual_result = api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(details, actual_result)

    def test_driver_private_data_update_with_delete_existing(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"key1": "val1", "key2": "val2", "key3": "val3"}
        details_update = {"key1": "val1_upd", "key4": "new_val"}

        # Create new details
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)
        api.driver_private_data_update(self.ctxt, test_host, test_id,
                                       details_update, delete_existing=True)

        actual_result = api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(details_update, actual_result)

    def test_driver_private_data_get(self):
        test_host, test_id = self._get_driver_test_data()
        test_key = "foo"
        test_keys = [test_key, "tee"]
        details = {test_keys[0]: "val", test_keys[1]: "val", "mee": "foo"}
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)

        actual_result_all = api.driver_private_data_get(
            self.ctxt, test_host, test_id)
        actual_result_single_key = api.driver_private_data_get(
            self.ctxt, test_host, test_id, test_key)
        actual_result_list = api.driver_private_data_get(
            self.ctxt, test_host, test_id, test_keys)

        self.assertEqual(details, actual_result_all)
        self.assertEqual(details[test_key], actual_result_single_key)
        self.assertEqual(dict.fromkeys(test_keys, "val"), actual_result_list)

    def test_driver_private_data_delete_single(self):
        test_host, test_id = self._get_driver_test_data()
        test_key = "foo"
        details = {test_key: "bar", "tee": "too"}
        valid_result = {"tee": "too"}
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)

        api.driver_private_data_delete(self.ctxt, test_host, test_id, test_key)

        actual_result = api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(valid_result, actual_result)

    def test_driver_private_data_delete_all(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"foo": "bar", "tee": "too"}
        api.driver_private_data_update(self.ctxt, test_host, test_id, details)

        api.driver_private_data_delete(self.ctxt, test_host, test_id)

        actual_result = api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual({}, actual_result)

    def test_custom_query(self):
        share = api.share_create(self.ctxt, {'host': 'foobar'})
        test_access_values = {
            'share_id': share['id'],
            'access_type': 'ip',
            'access_to': 'fake',
        }
        share_access = api.share_access_create(self.ctxt, test_access_values)

        api.share_access_delete(self.ctxt, share_access.id)
        self.assertRaises(exception.NotFound, api.share_access_get,
                          self.ctxt, share_access.id)
