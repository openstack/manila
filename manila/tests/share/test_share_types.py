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
import itertools

import ddt
import mock
from oslo_utils import strutils

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

    fake_required_extra_specs = {
        constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true',
    }

    fake_optional_extra_specs = {
        constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'true',
        constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: 'false',
        constants.ExtraSpecs.REVERT_TO_SNAPSHOT_SUPPORT: 'false',
    }

    fake_type_w_valid_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': fake_required_extra_specs,
            'required_extra_specs': fake_required_extra_specs,
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

    def test_get_extra_specs_from_share(self):
        expected = self.fake_extra_specs
        self.mock_object(share_types, 'get_share_type_extra_specs',
                         mock.Mock(return_value=expected))

        spec_value = share_types.get_extra_specs_from_share(self.fake_share)

        self.assertEqual(expected, spec_value)
        share_types.get_share_type_extra_specs.assert_called_once_with(
            self.fake_share_type_id)

    @ddt.data({}, {"fake": "fake"})
    def test_create_without_required_extra_spec(self, optional_specs):

        specs = copy.copy(self.fake_required_extra_specs)
        del specs['driver_handles_share_servers']
        specs.update(optional_specs)

        self.assertRaises(exception.InvalidShareType, share_types.create,
                          self.context, "fake_share_type", specs)

    @ddt.data({"snapshot_support": "fake"})
    def test_create_with_invalid_optional_extra_spec(self, optional_specs):

        specs = copy.copy(self.fake_required_extra_specs)
        specs.update(optional_specs)

        self.assertRaises(exception.InvalidShareType, share_types.create,
                          self.context, "fake_share_type", specs)

    def test_get_required_extra_specs(self):

        result = share_types.get_required_extra_specs()

        self.assertEqual(constants.ExtraSpecs.REQUIRED, result)

    def test_get_optional_extra_specs(self):

        result = share_types.get_optional_extra_specs()

        self.assertEqual(constants.ExtraSpecs.OPTIONAL, result)

    def test_get_tenant_visible_extra_specs(self):

        result = share_types.get_tenant_visible_extra_specs()

        self.assertEqual(constants.ExtraSpecs.TENANT_VISIBLE, result)

    def test_get_boolean_extra_specs(self):

        result = share_types.get_boolean_extra_specs()

        self.assertEqual(constants.ExtraSpecs.BOOLEAN, result)

    def test_is_valid_required_extra_spec_other(self):
        actual_result = share_types.is_valid_required_extra_spec(
            'fake', 'fake')

        self.assertIsNone(actual_result)

    @ddt.data(*itertools.product(
        constants.ExtraSpecs.REQUIRED,
        strutils.TRUE_STRINGS + strutils.FALSE_STRINGS))
    @ddt.unpack
    def test_is_valid_required_extra_spec_valid(self, key, value):
        actual_result = share_types.is_valid_required_extra_spec(key, value)

        self.assertTrue(actual_result)

    @ddt.data('invalid', {}, '0000000000')
    def test_is_valid_required_extra_spec_invalid(self, value):
        key = constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS
        actual_result = share_types.is_valid_required_extra_spec(key, value)

        self.assertFalse(actual_result)

    @ddt.data({},
              {'another_key': True})
    def test_get_valid_required_extra_specs_valid(self, optional_specs):

        specs = copy.copy(self.fake_required_extra_specs)
        specs.update(optional_specs)

        actual_result = share_types.get_valid_required_extra_specs(specs)

        self.assertEqual(self.fake_required_extra_specs, actual_result)

    @ddt.data(None,
              {},
              {constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'fake'})
    def test_get_valid_required_extra_specs_invalid(self, extra_specs):

        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.get_valid_required_extra_specs,
                          extra_specs)

    @ddt.data(*(
        list(itertools.product(
             (constants.ExtraSpecs.SNAPSHOT_SUPPORT,
              constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT,
              constants.ExtraSpecs.REVERT_TO_SNAPSHOT_SUPPORT,
              constants.ExtraSpecs.MOUNT_SNAPSHOT_SUPPORT),
             strutils.TRUE_STRINGS + strutils.FALSE_STRINGS))) +
        list(itertools.product(
             (constants.ExtraSpecs.REPLICATION_TYPE_SPEC,),
             constants.ExtraSpecs.REPLICATION_TYPES))
    )
    @ddt.unpack
    def test_is_valid_optional_extra_spec_valid(self, key, value):

        result = share_types.is_valid_optional_extra_spec(key, value)

        self.assertTrue(result)

    def test_is_valid_optional_extra_spec_valid_unknown_key(self):

        result = share_types.is_valid_optional_extra_spec('fake', 'fake')

        self.assertIsNone(result)

    def test_get_valid_optional_extra_specs(self):

        extra_specs = copy.copy(self.fake_required_extra_specs)
        extra_specs.update(self.fake_optional_extra_specs)
        extra_specs.update({'fake': 'fake'})

        result = share_types.get_valid_optional_extra_specs(extra_specs)

        self.assertEqual(self.fake_optional_extra_specs, result)

    def test_get_valid_optional_extra_specs_empty(self):

        result = share_types.get_valid_optional_extra_specs({})

        self.assertEqual({}, result)

    def test_get_valid_optional_extra_specs_invalid(self):

        extra_specs = {constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'fake'}

        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.get_valid_optional_extra_specs,
                          extra_specs)

    def test_add_access(self):
        project_id = '456'
        extra_specs = {
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true',
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'true',
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: 'false',
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
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'true',
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'true',
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: 'false',
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

    @ddt.data('<isnt> True', '<is> Wrong', None, 5)
    def test_parse_boolean_extra_spec_invalid(self, spec_value):

        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.parse_boolean_extra_spec,
                          'fake_key',
                          spec_value)
