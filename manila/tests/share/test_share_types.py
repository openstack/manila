# Copyright 2015 Deutsche Telekom AG.  All rights reserved.
# Copyright 2015 Tom Barron.  All rights reserved.
# Copyright 2015 Mirantis, Inc.  All rights reserved.
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


"""Test of Share Type methods for Manila."""
import copy
import datetime

import ddt
import mock

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import share_types
from manila import test


def create_share_type_dict(extra_specs=None):
    return {
        'fake_type': {
            'name': 'fake1',
            'extra_specs': extra_specs
        }
    }


@ddt.ddt
class ShareTypesTestCase(test.TestCase):

    fake_type = {
        'test': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 43, 24),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': {},
            'required_extra_specs': {},
            'id': u'fooid-1',
            'name': u'test',
            'updated_at': None
        }
    }
    fake_extra_specs = {u'gold': u'True'}
    fake_share_type_id = u'fooid-2'
    fake_type_w_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': fake_extra_specs,
            'required_extra_specs': {},
            'id': fake_share_type_id,
            'name': u'test_with_extra',
            'updated_at': None
        }
    }

    fake_type_w_valid_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': {
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
            },
            'required_extra_specs': {
                constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
            },
            'id': u'fooid-2',
            'name': u'test_with_extra',
            'updated_at': None
        }
    }

    fake_types = fake_type.copy()
    fake_types.update(fake_type_w_extra)
    fake_types.update(fake_type_w_valid_extra)

    fake_share = {'id': u'fooid-1', 'share_type_id': fake_share_type_id}

    def setUp(self):
        super(ShareTypesTestCase, self).setUp()
        self.context = context.get_admin_context()

    @ddt.data({}, fake_type, fake_type_w_extra, fake_types)
    def test_get_all_types(self, share_type):
        self.mock_object(db,
                         'share_type_get_all',
                         mock.Mock(return_value=copy.deepcopy(share_type)))
        returned_type = share_types.get_all_types(self.context)
        self.assertItemsEqual(share_type, returned_type)

    def test_get_all_types_search(self):
        share_type = self.fake_type_w_extra
        search_filter = {"extra_specs": {"gold": "True"}, 'is_public': True}
        self.mock_object(db,
                         'share_type_get_all',
                         mock.Mock(return_value=share_type))
        returned_type = share_types.get_all_types(self.context,
                                                  search_opts=search_filter)
        db.share_type_get_all.assert_called_once_with(
            mock.ANY, 0, filters={'is_public': True})
        self.assertItemsEqual(share_type, returned_type)
        search_filter = {"extra_specs": {"gold": "False"}}
        returned_type = share_types.get_all_types(self.context,
                                                  search_opts=search_filter)
        self.assertEqual({}, returned_type)

    def test_get_share_type_extra_specs(self):
        share_type = self.fake_type_w_extra['test_with_extra']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        id = share_type['id']
        extra_spec = share_types.get_share_type_extra_specs(id, key='gold')
        self.assertEqual(share_type['extra_specs']['gold'], extra_spec)
        extra_spec = share_types.get_share_type_extra_specs(id)
        self.assertEqual(share_type['extra_specs'], extra_spec)

    def test_share_types_diff(self):
        share_type1 = self.fake_type['test']
        share_type2 = self.fake_type_w_extra['test_with_extra']
        expeted_diff = {'extra_specs': {u'gold': (None, u'True')}}
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(side_effect=[share_type1, share_type2]))
        (diff, equal) = share_types.share_types_diff(self.context,
                                                     share_type1['id'],
                                                     share_type2['id'])
        self.assertFalse(equal)
        self.assertEqual(expeted_diff, diff)

    def test_share_types_diff_equal(self):
        share_type = self.fake_type['test']
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=share_type))
        (diff, equal) = share_types.share_types_diff(self.context,
                                                     share_type['id'],
                                                     share_type['id'])
        self.assertTrue(equal)

    def test_get_extra_specs_from_share(self):
        expected = self.fake_extra_specs
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value=expected))

        spec_value = share_types.get_extra_specs_from_share(self.fake_share)

        self.assertEqual(expected, spec_value)
        share_types.get_share_type_extra_specs.assert_called_once_with(
            self.fake_share_type_id)

    @ddt.data({},
              {"fake": "fake"},
              {constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: None})
    def test_create_without_required_extra_spec(self, extra_specs):
        name = "fake_share_type"

        self.assertRaises(exception.InvalidShareType, share_types.create,
                          self.context, name, extra_specs)

    def test_get_share_type_required_extra_specs(self):
        valid_required_extra_specs = (
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS,)

        actual_result = share_types.get_required_extra_specs()

        self.assertEqual(valid_required_extra_specs, actual_result)

    def test_validate_required_extra_spec_other(self):
        actual_result = share_types.is_valid_required_extra_spec(
            'fake', 'fake')

        self.assertIsNone(actual_result)

    @ddt.data('1', 'True', 'false', '0', True, False)
    def test_validate_required_extra_spec_valid(self, value):
        key = constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
        actual_result = share_types.is_valid_required_extra_spec(key, value)

        self.assertTrue(actual_result)

    @ddt.data('invalid', {}, '0000000000')
    def test_validate_required_extra_spec_invalid(self, value):
        key = constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
        actual_result = share_types.is_valid_required_extra_spec(key, value)

        self.assertFalse(actual_result)

    @ddt.data({constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'},
              {constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true',
               'another_key': True})
    def test_get_valid_required_extra_specs_valid(self, specs):
        actual_result = share_types.get_valid_required_extra_specs(specs)

        valid_result = {
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
        }
        self.assertEqual(valid_result, actual_result)

    @ddt.data(None, {})
    def test_get_valid_required_extra_specs_invalid(self, specs):
        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.get_valid_required_extra_specs, specs)

    def test_add_access(self):
        project_id = '456'
        extra_specs = {
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
        }
        share_type = share_types.create(self.context, 'type1', extra_specs)
        share_type_id = share_type.get('id')

        share_types.add_share_type_access(self.context, share_type_id,
                                          project_id)
        stype_access = db.share_type_access_get_all(self.context,
                                                    share_type_id)
        self.assertIn(project_id, [a.project_id for a in stype_access])

    def test_add_access_invalid(self):
        self.assertRaises(exception.InvalidShareType,
                          share_types.add_share_type_access,
                          'fake', None, 'fake')

    def test_remove_access(self):
        project_id = '456'
        extra_specs = {
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true'
        }
        share_type = share_types.create(
            self.context, 'type1', projects=['456'], extra_specs=extra_specs)
        share_type_id = share_type.get('id')

        share_types.remove_share_type_access(self.context, share_type_id,
                                             project_id)
        stype_access = db.share_type_access_get_all(self.context,
                                                    share_type_id)
        self.assertNotIn(project_id, stype_access)

    def test_remove_access_invalid(self):
        self.assertRaises(exception.InvalidShareType,
                          share_types.remove_share_type_access,
                          'fake', None, 'fake')

    @ddt.data({'spec_value': '<is> True', 'expected': True},
              {'spec_value': '<is>true', 'expected': True},
              {'spec_value': '<is> False', 'expected': False},
              {'spec_value': '<is>false', 'expected': False},
              {'spec_value': u' <is> FaLsE ', 'expected': False})
    @ddt.unpack
    def test_parse_boolean_extra_spec(self, spec_value, expected):

        result = share_types.parse_boolean_extra_spec('fake_key', spec_value)

        self.assertEqual(expected, result)

    @ddt.data('True', 'False', '<isnt> True', '<is> Wrong', None, 5)
    def test_parse_boolean_extra_spec_invalid(self, spec_value):

        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.parse_boolean_extra_spec,
                          'fake_key',
                          spec_value)
