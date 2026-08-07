# Copyright 2026 OpenStack Foundation.
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

"""Test of QoS Type methods for Manila."""

from manila.share import qos_types
from manila import test
from manila.tests import db_utils

FAKE_SHARE_WITHOUT_QOS = {
    'id': 'fake-share-id',
    'qos_type_id': None,
}


class QosTypesTestCase(test.TestCase):

    def setUp(self):
        super().setUp()
        self.qos_type = db_utils.create_qos_type()
        self.fake_share_with_qos = {
            'id': 'fake-share-id',
            'qos_type_id': self.qos_type['id'],
        }

    def test_get_qos_type_specs_all(self):
        result = qos_types.get_qos_type_specs(self.qos_type['id'])

        self.assertEqual(self.qos_type['specs'], result)

    def test_get_qos_type_specs_with_key(self):
        result = qos_types.get_qos_type_specs(
            self.qos_type['id'], key='key1')

        self.assertEqual('value1', result)

    def test_get_qos_type_specs_with_missing_key(self):
        result = qos_types.get_qos_type_specs(
            self.qos_type['id'], key='missing_key')

        self.assertIsNone(result)

    def test_get_specs_from_share_with_qos_type(self):
        result = qos_types.get_specs_from_share(self.fake_share_with_qos)

        self.assertEqual(self.qos_type['specs'], result)

    def test_get_specs_from_share_without_qos_type(self):
        result = qos_types.get_specs_from_share(FAKE_SHARE_WITHOUT_QOS)

        self.assertEqual({}, result)

    def test_get_qos_type_name_from_share_with_qos_type(self):
        result = qos_types.get_qos_type_name_from_share(
            self.fake_share_with_qos)

        self.assertEqual(self.qos_type['name'], result)

    def test_get_qos_type_name_from_share_without_qos_type(self):
        result = qos_types.get_qos_type_name_from_share(
            FAKE_SHARE_WITHOUT_QOS)

        self.assertEqual("", result)
