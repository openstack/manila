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
from unittest import mock


import ddt
from oslo_utils import strutils

from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import quota
from manila.share import share_types
from manila import test
from manila.tests import db_utils


def create_share_type_dict(extra_specs=None):
    return {
        'fake_type': {
            'name': 'fake1',
            'extra_specs': extra_specs
        }
    }


def return_share_type_update(context, id, values):
    name = values.get('name')
    description = values.get('description')
    is_public = values.get('is_public')
    if id == '444':
        raise exception.ShareTypeUpdateFailed(id=id)
    else:
        st_update = {
            'created_at': datetime.datetime(2019, 9, 9, 14, 40, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': {u'gold': u'True'},
            'required_extra_specs': {},
            'id': id,
            'name': name,
            'is_public': is_public,
            'description': description,
            'updated_at': None
        }
        return st_update


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

    fake_type_update = {
        'test_type_update': {
            'created_at': datetime.datetime(2019, 9, 9, 14, 40, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': {u'gold': u'True'},
            'required_extra_specs': {},
            'id': '888',
            'name': 'new_name',
            'is_public': True,
            'description': 'new_description',
            'updated_at': None
        }
    }

    fake_r_extra_specs = {
        u'gold': u'True',
        u'driver_handles_share_servers': u'True'
    }

    fake_r_required_extra_specs = {
        u'driver_handles_share_servers': u'True'
    }

    fake_r_type_extra = {
        'test_with_extra': {
            'created_at': datetime.datetime(2015, 1, 22, 11, 45, 31),
            'deleted': '0',
            'deleted_at': None,
            'extra_specs': fake_r_extra_specs,
            'required_extra_specs': fake_r_required_extra_specs,
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
        self.assertEqual(sorted(share_type), sorted(returned_type))

    def test_get_all_types_search(self):
        share_type = self.fake_type_w_extra
        search_filter = {'extra_specs': {'gold': 'True'}, 'is_public': True}
        self.mock_object(db,
                         'share_type_get_all',
                         mock.Mock(return_value=share_type))
        returned_type = share_types.get_all_types(self.context,
                                                  search_opts=search_filter)
        db.share_type_get_all.assert_called_once_with(
            mock.ANY, 0, filters={'is_public': True})

        self.assertEqual(sorted(share_type), sorted(returned_type))
        search_filter = {'extra_specs': {'gold': 'False'}}
        expected_types = {}
        returned_types = share_types.get_all_types(self.context,
                                                   search_opts=search_filter)
        self.assertEqual(expected_types, returned_types)

        share_type = self.fake_r_type_extra
        search_filter = {'extra_specs': {'gold': 'True'}}
        returned_type = share_types.get_all_types(self.context,
                                                  search_opts=search_filter)
        self.assertEqual(sorted(share_type), sorted(returned_type))

    @ddt.data("nova", "supernova,nova", "supernova",
              "nova,hypernova,supernova")
    def test_get_all_types_search_by_availability_zone(self, search_azs):
        all_share_types = {
            'gold': {
                'extra_specs': {
                    'somepoolcap': 'somevalue',
                    'availability_zones': 'nova,supernova,hypernova',
                },
                'required_extra_specs': {
                    'driver_handles_share_servers': True,
                },
                'id': '1e8f93a8-9669-4467-88a0-7b8229a9a609',
                'name': u'gold-share-type',
                'is_public': True,
            },
            'silver': {
                'extra_specs': {
                    'somepoolcap': 'somevalue',
                    'availability_zones': 'nova,supernova',
                },
                'required_extra_specs': {
                    'driver_handles_share_servers': False,
                },
                'id': '39a7b9a8-8c76-4b49-aed3-60b718d54325',
                'name': u'silver-share-type',
                'is_public': True,
            },
            'bronze': {
                'extra_specs': {
                    'somepoolcap': 'somevalue',
                    'availability_zones': 'milkyway,andromeda',
                },
                'required_extra_specs': {
                    'driver_handles_share_servers': True,
                },
                'id': '5a55a54d-6688-49b4-9344-bfc2d9634f70',
                'name': u'bronze-share-type',
                'is_public': True,
            },
            'default': {
                'extra_specs': {
                    'somepoolcap': 'somevalue',
                },
                'required_extra_specs': {
                    'driver_handles_share_servers': True,
                },
                'id': '5a55a54d-6688-49b4-9344-bfc2d9634f70',
                'name': u'bronze-share-type',
                'is_public': True,
            }
        }
        self.mock_object(
            db, 'share_type_get_all', mock.Mock(return_value=all_share_types))
        self.mock_object(share_types, 'get_valid_required_extra_specs')

        search_opts = {
            'extra_specs': {
                'somepoolcap': 'somevalue',
                'availability_zones': search_azs
            },
            'is_public': True,
        }
        returned_types = share_types.get_all_types(
            self.context, search_opts=search_opts)

        db.share_type_get_all.assert_called_once_with(
            mock.ANY, 0, filters={'is_public': True})

        expected_return_types = (['gold', 'silver', 'default']
                                 if len(search_azs.split(',')) < 3
                                 else ['gold', 'default'])
        self.assertEqual(sorted(expected_return_types),
                         sorted(returned_types))

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

    def test_update_share_type(self):
        expected = self.fake_type_update['test_type_update']
        self.mock_object(db,
                         'share_type_update',
                         mock.Mock(side_effect=return_share_type_update))
        self.mock_object(db,
                         'share_type_get',
                         mock.Mock(return_value=expected))
        new_name = "new_name"
        new_description = "new_description"
        is_public = True
        self.assertRaises(exception.ShareTypeUpdateFailed, share_types.update,
                          self.context, id='444', name=new_name,
                          description=new_description, is_public=is_public)
        share_types.update(self.context, '888', new_name,
                           new_description, is_public)
        st_update = share_types.get_share_type(self.context, '888')
        self.assertEqual(new_name, st_update['name'])
        self.assertEqual(new_description, st_update['description'])
        self.assertEqual(is_public, st_update['is_public'])

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
             strutils.TRUE_STRINGS + strutils.FALSE_STRINGS)) +
        list(itertools.product(
             (constants.ExtraSpecs.REPLICATION_TYPE_SPEC,),
             constants.ExtraSpecs.REPLICATION_TYPES)) +
        [(constants.ExtraSpecs.AVAILABILITY_ZONES, 'zone a, zoneb$c'),
         (constants.ExtraSpecs.AVAILABILITY_ZONES, '    zonea,    zoneb'),
         (constants.ExtraSpecs.AVAILABILITY_ZONES, 'zone1')]
    ))
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

    @ddt.data({constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'fake'},
              {constants.ExtraSpecs.AVAILABILITY_ZONES: 'ZoneA,'})
    def test_get_valid_optional_extra_specs_invalid(self, extra_specs):
        self.assertRaises(exception.InvalidExtraSpec,
                          share_types.get_valid_optional_extra_specs,
                          extra_specs)

    @ddt.data('      az 1,  az2 ,az 3  ', 'az 1,az2,az 3   ', None)
    def test_sanitize_extra_specs(self, spec_value):
        extra_specs = {
            constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS: 'True',
            constants.ExtraSpecs.SNAPSHOT_SUPPORT: 'True',
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT: 'False'
        }
        expected_specs = copy.copy(extra_specs)
        if spec_value is not None:
            extra_specs[constants.ExtraSpecs.AVAILABILITY_ZONES] = spec_value
            expected_specs['availability_zones'] = 'az 1,az2,az 3'

        self.assertDictEqual(expected_specs,
                             share_types.sanitize_extra_specs(extra_specs))

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

    def test_provision_filter_on_size(self):
        share_types.create(self.context, "type1",
                           extra_specs={
                               "key1": "val1",
                               "key2": "val2",
                               "driver_handles_share_servers": False})
        share_types.create(self.context, "type2",
                           extra_specs={
                               share_types.MIN_SIZE_KEY: "12",
                               "key3": "val3",
                               "driver_handles_share_servers": False})
        share_types.create(self.context, "type3",
                           extra_specs={
                               share_types.MAX_SIZE_KEY: "99",
                               "key4": "val4",
                               "driver_handles_share_servers": False})
        share_types.create(self.context, "type4",
                           extra_specs={
                               share_types.MIN_SIZE_KEY: "24",
                               share_types.MAX_SIZE_KEY: "99",
                               "key4": "val4",
                               "driver_handles_share_servers": False})
        share_types.create(self.context, "type5",
                           extra_specs={
                               share_types.MAX_SIZE_KEY: "95",
                               share_types.MAX_EXTEND_SIZE_KEY: "99",
                               "key4": "val4",
                               "driver_handles_share_servers": False})

        # Make sure we don't raise if there are no min/max set
        type1 = share_types.get_share_type_by_name(self.context, 'type1')
        share_types.provision_filter_on_size(self.context, type1, "11")

        # verify minimum size requirements
        type2 = share_types.get_share_type_by_name(self.context, 'type2')
        self.assertRaises(exception.InvalidInput,
                          share_types.provision_filter_on_size,
                          self.context, type2, "11")
        share_types.provision_filter_on_size(self.context, type2, "12")
        share_types.provision_filter_on_size(self.context, type2, "100")

        # verify max size requirements
        type3 = share_types.get_share_type_by_name(self.context, 'type3')
        self.assertRaises(exception.InvalidInput,
                          share_types.provision_filter_on_size,
                          self.context, type3, "100")
        share_types.provision_filter_on_size(self.context, type3, "99")
        share_types.provision_filter_on_size(self.context, type3, "1")

        # verify min and max
        type4 = share_types.get_share_type_by_name(self.context, 'type4')
        self.assertRaises(exception.InvalidInput,
                          share_types.provision_filter_on_size,
                          self.context, type4, "20")
        self.assertRaises(exception.InvalidInput,
                          share_types.provision_filter_on_size,
                          self.context, type4, "100")
        share_types.provision_filter_on_size(self.context, type4, "24")
        share_types.provision_filter_on_size(self.context, type4, "99")
        share_types.provision_filter_on_size(self.context, type4, "30")

        # verify max extend size requirements
        type5 = share_types.get_share_type_by_name(self.context, 'type5')
        self.assertRaises(exception.InvalidInput,
                          share_types.provision_filter_on_size,
                          self.context, type5, "100", operation="extend")
        share_types.provision_filter_on_size(self.context, type5, "99",
                                             operation="admin-extend")

    @ddt.data(True, False)
    def test__revert_allocated_share_type_quotas_during_migration(
            self, failed_on_reservation):
        fake_type_id = 'fake_1'
        extra_specs = {'replication_type': 'readable'}
        source_instance = db_utils.create_share()
        dest_instance = db_utils.create_share(
            share_type_id=fake_type_id)
        share_type = {
            'name': 'fake_share_type',
            'extra_specs': extra_specs,
            'is_public': True,
            'id': 'fake_type_id'
        }

        expected_deltas = {
            'project_id': dest_instance['project_id'],
            'user_id': dest_instance['user_id'],
            'share_replicas': -1,
            'replica_gigabytes': -dest_instance['size'],
            'share_type_id': share_type['id'],
            'shares': -1,
            'gigabytes': -dest_instance['size'],
        }
        reservations = 'reservations'
        reservation_action = (
            mock.Mock(side_effect=exception.ManilaException(message='fake'))
            if failed_on_reservation else mock.Mock(return_value=reservations))

        mock_type_get = self.mock_object(
            share_types, 'get_share_type', mock.Mock(return_value=share_type))
        mock_reserve = self.mock_object(
            quota.QUOTAS, 'reserve', reservation_action)
        mock_commit = self.mock_object(quota.QUOTAS, 'commit')
        mock_log = self.mock_object(share_types.LOG, 'exception')

        share_types.revert_allocated_share_type_quotas_during_migration(
            self.context, source_instance, share_type['id'], dest_instance)

        if not failed_on_reservation:
            mock_commit.assert_called_once_with(
                self.context, reservations,
                project_id=dest_instance['project_id'],
                user_id=dest_instance['user_id'],
                share_type_id=share_type['id'])
        else:
            mock_log.assert_called_once()

        mock_type_get.assert_called_once_with(
            self.context, share_type['id'])
        mock_reserve.assert_called_once_with(
            self.context, **expected_deltas)
