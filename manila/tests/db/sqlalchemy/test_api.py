# Copyright 2013 OpenStack Foundation
# Copyright (c) 2014 NetApp, Inc.
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

import copy
import datetime
import random
from unittest import mock

import ddt
from oslo_db import exception as db_exception
from oslo_utils import timeutils
from oslo_utils import uuidutils

from manila.common import constants
from manila import context
from manila.db.sqlalchemy import api as db_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import quota
from manila import test
from manila.tests import db_utils

QUOTAS = quota.QUOTAS

security_service_dict = {
    'id': 'fake id',
    'project_id': 'fake project',
    'type': 'ldap',
    'dns_ip': 'fake dns',
    'server': 'fake ldap server',
    'domain': 'fake ldap domain',
    'default_ad_site': 'fake ldap default_ad_site',
    'ou': 'fake ldap ou',
    'user': 'fake user',
    'password': 'fake password',
    'name': 'whatever',
    'description': 'nevermind',
}


class BaseDatabaseAPITestCase(test.TestCase):
    def _check_fields(self, expected, actual):
        for key in expected:
            self.assertEqual(expected[key], actual[key])


@ddt.ddt
class GenericDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(GenericDatabaseAPITestCase, self).setUp()
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

        db_api.ensure_model_dict_has_id(values)

        self.assertEqual(call_count, uuidutils.generate_uuid.call_count)
        self.assertIn('id', values)

    def test_custom_query(self):
        share = db_utils.create_share()
        share_access = db_utils.create_access(share_id=share['id'])

        db_api.share_instance_access_delete(
            self.ctxt, share_access.instance_mappings[0].id)
        self.assertRaises(exception.NotFound, db_api.share_access_get,
                          self.ctxt, share_access.id)


@ddt.ddt
class ShareAccessDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareAccessDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    @ddt.data(0, 3)
    def test_share_access_get_all_for_share(self, len_rules):
        share = db_utils.create_share()
        rules = [db_utils.create_access(share_id=share['id'])
                 for i in range(0, len_rules)]
        rule_ids = [r['id'] for r in rules]

        result = db_api.share_access_get_all_for_share(self.ctxt, share['id'])

        self.assertEqual(len_rules, len(result))
        result_ids = [r['id'] for r in result]
        self.assertEqual(rule_ids, result_ids)

    def test_share_access_get_all_for_share_no_instance_mappings(self):
        share = db_utils.create_share()
        share_instance = share['instance']
        rule = db_utils.create_access(share_id=share['id'])
        # Mark instance mapping soft deleted
        db_api.share_instance_access_update(
            self.ctxt, rule['id'], share_instance['id'], {'deleted': "True"})

        result = db_api.share_access_get_all_for_share(self.ctxt, share['id'])

        self.assertEqual([], result)

    def test_share_instance_access_update(self):
        share = db_utils.create_share()
        access = db_utils.create_access(share_id=share['id'])

        instance_access_mapping = db_api.share_instance_access_get(
            self.ctxt, access['id'], share.instance['id'])
        self.assertEqual(constants.ACCESS_STATE_QUEUED_TO_APPLY,
                         access['state'])
        self.assertIsNone(access['access_key'])

        db_api.share_instance_access_update(
            self.ctxt, access['id'], share.instance['id'],
            {'state': constants.STATUS_ERROR, 'access_key': 'watson4heisman'})

        instance_access_mapping = db_api.share_instance_access_get(
            self.ctxt, access['id'], share.instance['id'])
        access = db_api.share_access_get(self.ctxt, access['id'])
        self.assertEqual(constants.STATUS_ERROR,
                         instance_access_mapping['state'])
        self.assertEqual('watson4heisman', access['access_key'])
        self.assertIsNotNone(access['updated_at'])
        time_now = timeutils.utcnow()
        self.assertTrue(access['updated_at'] < time_now)
        self.assertTrue(instance_access_mapping['updated_at'] < time_now)

    @ddt.data(True, False)
    def test_share_access_get_all_for_instance_with_share_access_data(
            self, with_share_access_data):
        share = db_utils.create_share()
        access_1 = db_utils.create_access(share_id=share['id'])
        access_2 = db_utils.create_access(share_id=share['id'])
        share_access_keys = ('access_to', 'access_type', 'access_level',
                             'share_id')

        rules = db_api.share_access_get_all_for_instance(
            self.ctxt, share.instance['id'],
            with_share_access_data=with_share_access_data)

        share_access_keys_present = True if with_share_access_data else False
        actual_access_ids = [r['access_id'] for r in rules]
        self.assertTrue(isinstance(actual_access_ids, list))
        expected = [access_1['id'], access_2['id']]
        self.assertEqual(len(expected), len(actual_access_ids))
        for pool in expected:
            self.assertIn(pool, actual_access_ids)
        for rule in rules:
            for key in share_access_keys:
                self.assertEqual(share_access_keys_present, key in rule)
            self.assertIn('state', rule)

    def test_share_access_get_all_for_instance_with_filters(self):
        share = db_utils.create_share()
        new_share_instance = db_utils.create_share_instance(
            share_id=share['id'])
        access_1 = db_utils.create_access(share_id=share['id'])
        access_2 = db_utils.create_access(share_id=share['id'])
        share_access_keys = ('access_to', 'access_type', 'access_level',
                             'share_id')
        db_api.share_instance_access_update(
            self.ctxt, access_1['id'], new_share_instance['id'],
            {'state': constants.STATUS_ACTIVE})

        rules = db_api.share_access_get_all_for_instance(
            self.ctxt, new_share_instance['id'],
            filters={'state': constants.ACCESS_STATE_QUEUED_TO_APPLY})

        self.assertEqual(1, len(rules))
        self.assertEqual(access_2['id'], rules[0]['access_id'])

        for rule in rules:
            for key in share_access_keys:
                self.assertIn(key, rule)

    def test_share_instance_access_delete(self):
        share = db_utils.create_share()
        access = db_utils.create_access(share_id=share['id'],
                                        metadata={'key1': 'v1'})
        instance_access_mapping = db_api.share_instance_access_get(
            self.ctxt, access['id'], share.instance['id'])

        db_api.share_instance_access_delete(
            self.ctxt, instance_access_mapping['id'])

        rules = db_api.share_access_get_all_for_instance(
            self.ctxt, share.instance['id'])
        self.assertEqual([], rules)

        self.assertRaises(exception.NotFound, db_api.share_instance_access_get,
                          self.ctxt, access['id'], share['instance']['id'])

    def test_one_share_with_two_share_instance_access_delete(self):
        metadata = {'key2': 'v2', 'key3': 'v3'}
        share = db_utils.create_share()
        instance = db_utils.create_share_instance(share_id=share['id'])
        access = db_utils.create_access(share_id=share['id'],
                                        metadata=metadata)
        instance_access_mapping1 = db_api.share_instance_access_get(
            self.ctxt, access['id'], share.instance['id'])
        instance_access_mapping2 = db_api.share_instance_access_get(
            self.ctxt, access['id'], instance['id'])
        self.assertEqual(instance_access_mapping1['access_id'],
                         instance_access_mapping2['access_id'])
        db_api.share_instance_delete(self.ctxt, instance['id'])

        get_accesses = db_api.share_access_get_all_for_share(self.ctxt,
                                                             share['id'])
        self.assertEqual(1, len(get_accesses))
        get_metadata = (
            get_accesses[0].get('share_access_rules_metadata') or {})
        get_metadata = {item['key']: item['value'] for item in get_metadata}
        self.assertEqual(metadata, get_metadata)
        self.assertEqual(access['id'], get_accesses[0]['id'])

        db_api.share_instance_delete(self.ctxt, share['instance']['id'])
        self.assertRaises(exception.NotFound,
                          db_api.share_instance_access_get,
                          self.ctxt, access['id'], share['instance']['id'])

        get_accesses = db_api.share_access_get_all_for_share(self.ctxt,
                                                             share['id'])
        self.assertEqual(0, len(get_accesses))

    @ddt.data(True, False)
    def test_share_instance_access_get_with_share_access_data(
            self, with_share_access_data):
        share = db_utils.create_share()
        access = db_utils.create_access(share_id=share['id'])

        instance_access = db_api.share_instance_access_get(
            self.ctxt, access['id'], share['instance']['id'],
            with_share_access_data=with_share_access_data)

        for key in ('share_id', 'access_type', 'access_to', 'access_level',
                    'access_key'):
            self.assertEqual(with_share_access_data, key in instance_access)

    @ddt.data({'existing': {'access_type': 'cephx', 'access_to': 'alice'},
               'new': {'access_type': 'user', 'access_to': 'alice'},
               'result': False},
              {'existing': {'access_type': 'user', 'access_to': 'bob'},
               'new': {'access_type': 'user', 'access_to': 'bob'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.0.0.10/32'},
               'new': {'access_type': 'ip', 'access_to': '10.0.0.10'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.10.0.11'},
               'new': {'access_type': 'ip', 'access_to': '10.10.0.11'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': 'fd21::11'},
               'new': {'access_type': 'ip', 'access_to': 'fd21::11'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': 'fd21::10'},
               'new': {'access_type': 'ip', 'access_to': 'fd21::10/128'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.10.0.0/22'},
               'new': {'access_type': 'ip', 'access_to': '10.10.0.0/24'},
               'result': False},
              {'existing': {'access_type': 'ip', 'access_to': '2620:52::/48'},
               'new': {'access_type': 'ip',
                       'access_to': '2620:52:0:13b8::/64'},
               'result': False})
    @ddt.unpack
    def test_share_access_check_for_existing_access(self, existing, new,
                                                    result):
        share = db_utils.create_share()
        db_utils.create_access(share_id=share['id'],
                               access_type=existing['access_type'],
                               access_to=existing['access_to'])

        rule_exists = db_api.share_access_check_for_existing_access(
            self.ctxt, share['id'], new['access_type'], new['access_to'])

        self.assertEqual(result, rule_exists)

    def test_share_access_get_all_for_share_with_metadata(self):
        share = db_utils.create_share()
        rules = [db_utils.create_access(
            share_id=share['id'], metadata={'key1': i})
            for i in range(0, 3)]
        rule_ids = [r['id'] for r in rules]

        result = db_api.share_access_get_all_for_share(self.ctxt, share['id'])

        self.assertEqual(3, len(result))
        result_ids = [r['id'] for r in result]
        self.assertEqual(rule_ids, result_ids)

        result = db_api.share_access_get_all_for_share(
            self.ctxt, share['id'], {'metadata': {'key1': '2'}})
        self.assertEqual(1, len(result))
        self.assertEqual(rules[2]['id'], result[0]['id'])

    def test_share_access_metadata_update(self):
        share = db_utils.create_share()
        new_metadata = {'key1': 'test_update', 'key2': 'v2'}
        rule = db_utils.create_access(share_id=share['id'],
                                      metadata={'key1': 'v1'})
        result_metadata = db_api.share_access_metadata_update(
            self.ctxt, rule['id'], metadata=new_metadata)
        result = db_api.share_access_get(self.ctxt, rule['id'])
        self.assertEqual(new_metadata, result_metadata)
        metadata = result.get('share_access_rules_metadata')
        if metadata:
            metadata = {item['key']: item['value'] for item in metadata}
        else:
            metadata = {}
        self.assertEqual(new_metadata, metadata)

    def test_share_access_get_with_context(self):
        ctxt = context.RequestContext('demo', 'fake', False)
        share = db_utils.create_share(project_id=ctxt.project_id)
        rules = [db_utils.create_access(share_id=share['id'])]

        result = db_api.share_access_get_with_context(ctxt, rules[0]['id'])

        self.assertEqual(result['project_id'], ctxt.project_id)

    def test_share_access_get_with_context_not_found(self):

        self.assertRaises(
            exception.NotFound,
            db_api.share_access_get_with_context,
            self.ctxt,
            'fake_rule_id')


@ddt.ddt
class ShareDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    @ddt.data('yes', 'no', 'only')
    def test_share_read_deleted(self, read_deleted):
        share = db_utils.create_share()
        test_ctxt = context.get_admin_context(read_deleted=read_deleted)
        admin_ctxt = context.get_admin_context(read_deleted='yes')

        if read_deleted in ('yes', 'no'):
            self.assertIsNotNone(db_api.share_get(test_ctxt, share['id']))
        elif read_deleted == 'only':
            self.assertRaises(exception.NotFound, db_api.share_get,
                              test_ctxt, share['id'])

        # we don't use the to be tested context here and
        # we need to delete the share instance before we can delete the share
        db_api.share_instance_delete(admin_ctxt, share['instance']['id'])
        db_api.share_delete(admin_ctxt, share['id'])

        if read_deleted in ('yes', 'only'):
            self.assertIsNotNone(db_api.share_get(test_ctxt, share['id']))
        elif read_deleted == 'no':
            self.assertRaises(exception.NotFound, db_api.share_get,
                              test_ctxt, share['id'])

    def test_share_filter_by_host_with_pools(self):
        share_instances = [[
            db_api.share_create(self.ctxt, {'host': value}).instance
            for value in ('foo', 'foo#pool0')]]

        db_utils.create_share()
        self._assertEqualListsOfObjects(share_instances[0],
                                        db_api.share_instances_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])

    def test_share_filter_all_by_host_with_pools_multiple_hosts(self):
        share_instances = [[
            db_api.share_create(self.ctxt, {'host': value}).instance
            for value in ('foo', 'foo#pool0', 'foo', 'foo#pool1')]]

        db_utils.create_share()
        self._assertEqualListsOfObjects(share_instances[0],
                                        db_api.share_instances_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])

    def test_share_filter_all_by_share_server(self):
        share_network = db_utils.create_share_network()
        share_server = db_utils.create_share_server()
        share = db_utils.create_share(share_server_id=share_server['id'],
                                      share_network_id=share_network['id'])

        actual_result = db_api.share_get_all_by_share_server(
            self.ctxt, share_server['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_in_recycle_bin_filter_all_by_share_server(self):
        share_network = db_utils.create_share_network()
        share_server = db_utils.create_share_server()
        share = db_utils.create_share(share_server_id=share_server['id'],
                                      share_network_id=share_network['id'],
                                      is_soft_deleted=True)

        actual_result = db_api.get_shares_in_recycle_bin_by_share_server(
            self.ctxt, share_server['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_in_recycle_bin_filter_all_by_share_network(self):
        share_network = db_utils.create_share_network()
        share_server = db_utils.create_share_server()
        share = db_utils.create_share(share_server_id=share_server['id'],
                                      share_network_id=share_network['id'],
                                      is_soft_deleted=True)

        actual_result = db_api.get_shares_in_recycle_bin_by_network(
            self.ctxt, share_network['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_filter_all_by_share_group(self):
        group = db_utils.create_share_group()
        share = db_utils.create_share(share_group_id=group['id'])

        actual_result = db_api.share_get_all_by_share_group_id(
            self.ctxt, group['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_instance_delete_with_share(self):
        share = db_utils.create_share()

        self.assertIsNotNone(db_api.share_get(self.ctxt, share['id']))
        self.assertIsNotNone(db_api.share_metadata_get(self.ctxt, share['id']))

        db_api.share_instance_delete(self.ctxt, share.instance['id'])

        self.assertRaises(exception.NotFound, db_api.share_get,
                          self.ctxt, share['id'])
        self.assertRaises(exception.NotFound, db_api.share_metadata_get,
                          self.ctxt, share['id'])

    def test_share_instance_delete_with_share_need_to_update_usages(self):
        share = db_utils.create_share()

        self.assertIsNotNone(db_api.share_get(self.ctxt, share['id']))
        self.assertIsNotNone(db_api.share_metadata_get(self.ctxt, share['id']))

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')

        db_api.share_instance_delete(
            self.ctxt, share.instance['id'], need_to_update_usages=True)

        self.assertRaises(exception.NotFound, db_api.share_get,
                          self.ctxt, share['id'])
        self.assertRaises(exception.NotFound, db_api.share_metadata_get,
                          self.ctxt, share['id'])
        quota.QUOTAS.reserve.assert_called_once_with(
            self.ctxt,
            project_id=share['project_id'],
            shares=-1,
            gigabytes=-share['size'],
            share_type_id=None,
            user_id=share['user_id']
        )
        quota.QUOTAS.commit.assert_called_once_with(
            self.ctxt,
            mock.ANY,
            project_id=share['project_id'],
            share_type_id=None,
            user_id=share['user_id']
        )

    def test_share_instance_get(self):
        share = db_utils.create_share()

        instance = db_api.share_instance_get(self.ctxt, share.instance['id'])

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    @ddt.data({'with_share_data': True, 'status': constants.STATUS_AVAILABLE},
              {'with_share_data': False, 'status': None})
    @ddt.unpack
    def test_share_instance_get_all_by_host(self, with_share_data, status):
        kwargs = {'status': status} if status else {}
        db_utils.create_share(**kwargs)
        instances = db_api.share_instances_get_all_by_host(
            self.ctxt, 'fake_host', with_share_data=with_share_data,
            status=status)

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

        if with_share_data:
            self.assertEqual('NFS', instance['share_proto'])
            self.assertEqual(0, instance['size'])
        else:
            self.assertNotIn('share_proto', instance)

    def test_share_instance_get_all_by_host_not_found_exception(self):
        db_utils.create_share()
        self.mock_object(db_api, 'share_get', mock.Mock(
                         side_effect=exception.NotFound))
        instances = db_api.share_instances_get_all_by_host(
            self.ctxt, 'fake_host', True)

        self.assertEqual(0, len(instances))

    def test_share_instance_get_all_by_share_group(self):
        group = db_utils.create_share_group()
        db_utils.create_share(share_group_id=group['id'])
        db_utils.create_share()

        instances = db_api.share_instances_get_all_by_share_group_id(
            self.ctxt, group['id'])

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    @ddt.data('id', 'path')
    def test_share_instance_get_all_by_export_location(self, type):
        share = db_utils.create_share()
        initial_location = ['fake_export_location']
        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_location, False)

        if type == 'id':
            export_location = (
                db_api.share_export_locations_get_by_share_id(self.ctxt,
                                                              share['id']))
            value = export_location[0]['uuid']
        else:
            value = 'fake_export_location'

        instances = db_api.share_instances_get_all(
            self.ctxt, filters={'export_location_' + type: value})

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    def test_share_instance_get_all_by_is_soft_deleted(self):
        db_utils.create_share()
        db_utils.create_share(is_soft_deleted=True)

        instances = db_api.share_instances_get_all(
            self.ctxt, filters={'is_soft_deleted': True})

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    def test_share_instance_get_all_by_ids(self):
        fake_share = db_utils.create_share()
        expected_share_instance = db_utils.create_share_instance(
            share_id=fake_share['id'])

        # Populate the db with a dummy share
        db_utils.create_share_instance(share_id=fake_share['id'])

        instances = db_api.share_instances_get_all(
            self.ctxt,
            filters={'instance_ids': [expected_share_instance['id']]})

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    @ddt.data('host', 'share_group_id')
    def test_share_get_all_sort_by_share_instance_fields(self, sort_key):
        shares = [db_utils.create_share(**{sort_key: n, 'size': 1})
                  for n in ('test1', 'test2')]

        actual_result = db_api.share_get_all(
            self.ctxt, sort_key=sort_key, sort_dir='desc')

        self.assertEqual(2, len(actual_result))
        self.assertEqual(shares[0]['id'], actual_result[1]['id'])

    @ddt.data('id')
    def test_share_get_all_sort_by_share_fields(self, sort_key):
        shares = [db_utils.create_share(**{sort_key: n, 'size': 1})
                  for n in ('FAKE_UUID1', 'FAKE_UUID2')]

        actual_result = db_api.share_get_all(
            self.ctxt, sort_key=sort_key, sort_dir='desc')

        self.assertEqual(2, len(actual_result))
        self.assertEqual(shares[0]['id'], actual_result[1]['id'])

    @ddt.data('id', 'path')
    def test_share_get_all_by_export_location(self, type):
        share = db_utils.create_share()
        initial_location = ['fake_export_location']
        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_location, False)
        if type == 'id':
            export_location = db_api.share_export_locations_get_by_share_id(
                self.ctxt, share['id'])
            value = export_location[0]['uuid']
        else:
            value = 'fake_export_location'

        actual_result = db_api.share_get_all(
            self.ctxt, filters={'export_location_' + type: value})

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0]['id'])

    @ddt.data('id', 'path')
    def test_share_get_all_by_export_location_not_exist(self, type):
        share = db_utils.create_share()
        initial_location = ['fake_export_location']
        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_location, False)
        filter = {'export_location_' + type: 'export_location_not_exist'}
        actual_result = db_api.share_get_all(self.ctxt, filters=filter)

        self.assertEqual(0, len(actual_result))

    @ddt.data((10, 5), (20, 5))
    @ddt.unpack
    def test_share_get_all_with_limit(self, limit, offset):
        for i in range(limit + 5):
            db_utils.create_share()

        filters = {'limit': offset, 'offset': 0}
        shares_not_requested = db_api.share_get_all(
            self.ctxt, filters=filters)

        filters = {'limit': limit, 'offset': offset}
        shares_requested = db_api.share_get_all(self.ctxt, filters=filters)

        shares_not_requested_ids = [s['id'] for s in shares_not_requested]
        shares_requested_ids = [s['id'] for s in shares_requested]

        self.assertEqual(offset, len(shares_not_requested_ids))
        self.assertEqual(limit, len(shares_requested_ids))
        self.assertEqual(0, len(
            set(shares_requested_ids) & set(shares_not_requested_ids)))

    @ddt.data(
        ({'display_name~': 'fake_name'}, 3, 3),
        ({'display_name~': 'fake_name', 'limit': 2}, 3, 2)
    )
    @ddt.unpack
    def test_share_get_all_with_count(self, filters, amount_of_shares,
                                      expected_shares_len):
        [db_utils.create_share(display_name='fake_name_%s' % str(i))
         for i in range(amount_of_shares)]

        count, shares = db_api.share_get_all_with_count(
            self.ctxt, filters=filters)

        self.assertEqual(count, amount_of_shares)
        for share in shares:
            self.assertIn('fake_name', share['display_name'])
        self.assertEqual(expected_shares_len, len(shares))

    def test_share_get_all_by_share_group_id_with_count(self):
        share_groups = [db_utils.create_share_group() for i in range(2)]
        shares = [
            db_utils.create_share(share_group_id=share_group['id'])
            for share_group in share_groups]

        count, result = db_api.share_get_all_by_share_group_id_with_count(
            self.ctxt, share_groups[0]['id'])

        self.assertEqual(count, 1)
        self.assertEqual(shares[0]['id'], result[0]['id'])
        self.assertEqual(1, len(result))

    def test_share_get_all_by_share_server_with_count(self):
        share_servers = [db_utils.create_share_server() for i in range(2)]
        shares = [
            db_utils.create_share(share_server_id=share_server['id'])
            for share_server in share_servers]

        count, result = db_api.share_get_all_by_share_server_with_count(
            self.ctxt, share_servers[0]['id'])

        self.assertEqual(count, 1)
        self.assertEqual(shares[0]['id'], result[0]['id'])
        self.assertEqual(1, len(result))

    def test_share_get_all_by_project_with_count(self):
        project_ids = ['fake_id_1', 'fake_id_2']
        shares = [
            db_utils.create_share(project_id=project_id)
            for project_id in project_ids]

        count, result = db_api.share_get_all_by_project_with_count(
            self.ctxt, project_ids[0])

        self.assertEqual(count, 1)
        self.assertEqual(shares[0]['id'], result[0]['id'])
        self.assertEqual(1, len(result))

    def test_share_get_all_expired(self):
        now_time = timeutils.utcnow()
        time_delta = datetime.timedelta(seconds=3600)
        time1 = now_time + time_delta
        time2 = now_time - time_delta
        share1 = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                       is_soft_deleted=False,
                                       scheduled_to_be_deleted_at=None)
        share2 = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                       is_soft_deleted=True,
                                       scheduled_to_be_deleted_at=time1)
        share3 = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                       is_soft_deleted=True,
                                       scheduled_to_be_deleted_at=time2)
        shares = [share1, share2, share3]
        result = db_api.get_all_expired_shares(self.ctxt)
        self.assertEqual(1, len(result))
        self.assertEqual(shares[2]['id'], result[0]['id'])

    @ddt.data(
        ({'status': constants.STATUS_AVAILABLE}, 'status',
         [constants.STATUS_AVAILABLE, constants.STATUS_ERROR]),
        ({'share_group_id': 'fake_group_id'}, 'share_group_id',
         ['fake_group_id', 'group_id']),
        ({'snapshot_id': 'fake_snapshot_id'}, 'snapshot_id',
         ['fake_snapshot_id', 'snapshot_id']),
        ({'share_type_id': 'fake_type_id'}, 'share_type_id',
         ['fake_type_id', 'type_id']),
        ({'host': 'fakehost@fakebackend#fakepool'}, 'host',
         ['fakehost@fakebackend#fakepool', 'foo@bar#test']),
        ({'share_network_id': 'fake_net_id'}, 'share_network_id',
         ['fake_net_id', 'net_id']),
        ({'display_name': 'fake_share_name'}, 'display_name',
         ['fake_share_name', 'share_name']),
        ({'display_description': 'fake description'}, 'display_description',
         ['fake description', 'description']),
        ({'is_soft_deleted': True}, 'is_soft_deleted',
         [True, False])
    )
    @ddt.unpack
    def test_share_get_all_with_filters(self, filters, key, share_values):
        for value in share_values:
            kwargs = {key: value}
            db_utils.create_share(**kwargs)

        results = db_api.share_get_all(self.ctxt, filters=filters)

        for share in results:
            self.assertEqual(share[key], filters[key])

    @ddt.data(
        ('display_name~', 'display_name',
         ['fake_name_1', 'fake_name_2', 'fake_name_3'], 'fake_name'),
        ('display_description~', 'display_description',
         ['fake desc 1', 'fake desc 2', 'fake desc 3'], 'fake desc')
    )
    @ddt.unpack
    def test_share_get_all_like_filters(
            self, filter_name, key, share_values, like_value):
        for value in share_values:
            kwargs = {key: value}
            db_utils.create_share(**kwargs)
        db_utils.create_share(
            display_name='irrelevant_name',
            display_description='should not be queried')

        filters = {filter_name: like_value}

        results = db_api.share_get_all(self.ctxt, filters=filters)

        self.assertEqual(len(share_values), len(results))

    @ddt.data(None, 'writable')
    def test_share_get_has_replicas_field(self, replication_type):
        share = db_utils.create_share(replication_type=replication_type)

        db_share = db_api.share_get(self.ctxt, share['id'])

        self.assertIn('has_replicas', db_share)

    @ddt.data({'with_share_data': False, 'with_share_server': False},
              {'with_share_data': False, 'with_share_server': True},
              {'with_share_data': True, 'with_share_server': False},
              {'with_share_data': True, 'with_share_server': True})
    @ddt.unpack
    def test_share_replicas_get_all(self, with_share_data,
                                    with_share_server):
        share_server = db_utils.create_share_server()
        share_1 = db_utils.create_share()
        share_2 = db_utils.create_share()
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_id=share_1['id'],
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            share_id=share_1['id'],
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC,
            share_id=share_2['id'],
            share_server_id=share_server['id'])
        db_utils.create_share_replica(share_id=share_2['id'])
        expected_ss_keys = {
            'backend_details', 'host', 'id',
            'share_network_subnet_ids', 'status',
        }
        expected_share_keys = {
            'project_id', 'share_type_id', 'display_name',
            'name', 'share_proto', 'is_public',
            'source_share_group_snapshot_member_id',
        }
        session = db_api.get_session()

        with session.begin():
            share_replicas = db_api.share_replicas_get_all(
                self.ctxt, with_share_server=with_share_server,
                with_share_data=with_share_data, session=session)

            self.assertEqual(3, len(share_replicas))
            for replica in share_replicas:
                if with_share_server:
                    self.assertTrue(expected_ss_keys.issubset(
                        replica['share_server'].keys()))
                else:
                    self.assertNotIn('share_server', replica.keys())
                    self.assertEqual(
                        with_share_data,
                        expected_share_keys.issubset(replica.keys()))

    @ddt.data({'with_share_data': False, 'with_share_server': False},
              {'with_share_data': False, 'with_share_server': True},
              {'with_share_data': True, 'with_share_server': False},
              {'with_share_data': True, 'with_share_server': True})
    @ddt.unpack
    def test_share_replicas_get_all_by_share(self, with_share_data,
                                             with_share_server):
        share_server = db_utils.create_share_server()
        share = db_utils.create_share()
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_id=share['id'],
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            share_id=share['id'],
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC,
            share_id=share['id'],
            share_server_id=share_server['id'])
        expected_ss_keys = {
            'backend_details', 'host', 'id',
            'share_network_subnet_ids', 'status',
        }
        expected_share_keys = {
            'project_id', 'share_type_id', 'display_name',
            'name', 'share_proto', 'is_public',
            'source_share_group_snapshot_member_id',
        }
        session = db_api.get_session()

        with session.begin():
            share_replicas = db_api.share_replicas_get_all_by_share(
                self.ctxt, share['id'],
                with_share_server=with_share_server,
                with_share_data=with_share_data, session=session)

            self.assertEqual(3, len(share_replicas))
            for replica in share_replicas:
                if with_share_server:
                    self.assertTrue(expected_ss_keys.issubset(
                        replica['share_server'].keys()))
                else:
                    self.assertNotIn('share_server', replica.keys())
                self.assertEqual(with_share_data,
                                 expected_share_keys.issubset(replica.keys()))

    def test_share_replicas_get_available_active_replica(self):
        share_server = db_utils.create_share_server()
        share_1 = db_utils.create_share()
        share_2 = db_utils.create_share()
        share_3 = db_utils.create_share()
        db_utils.create_share_replica(
            id='Replica1',
            share_id=share_1['id'],
            status=constants.STATUS_AVAILABLE,
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            id='Replica2',
            status=constants.STATUS_AVAILABLE,
            share_id=share_1['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_server_id=share_server['id'])
        db_utils.create_share_replica(
            id='Replica3',
            status=constants.STATUS_AVAILABLE,
            share_id=share_2['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE)
        db_utils.create_share_replica(
            id='Replica4',
            status=constants.STATUS_ERROR,
            share_id=share_2['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE)
        db_utils.create_share_replica(
            id='Replica5',
            status=constants.STATUS_AVAILABLE,
            share_id=share_2['id'],
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        db_utils.create_share_replica(
            id='Replica6',
            share_id=share_3['id'],
            status=constants.STATUS_AVAILABLE,
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        session = db_api.get_session()
        expected_ss_keys = {
            'backend_details', 'host', 'id',
            'share_network_subnet_ids', 'status',
        }
        expected_share_keys = {
            'project_id', 'share_type_id', 'display_name',
            'name', 'share_proto', 'is_public',
            'source_share_group_snapshot_member_id',
        }

        with session.begin():
            replica_share_1 = (
                db_api.share_replicas_get_available_active_replica(
                    self.ctxt, share_1['id'], with_share_server=True,
                    session=session)
            )
            replica_share_2 = (
                db_api.share_replicas_get_available_active_replica(
                    self.ctxt, share_2['id'], with_share_data=True,
                    session=session)
            )
            replica_share_3 = (
                db_api.share_replicas_get_available_active_replica(
                    self.ctxt, share_3['id'], session=session)
            )

            self.assertIn(replica_share_1.get('id'), ['Replica1', 'Replica2'])
            self.assertTrue(expected_ss_keys.issubset(
                replica_share_1['share_server'].keys()))
            self.assertFalse(
                expected_share_keys.issubset(replica_share_1.keys()))
            self.assertEqual(replica_share_2.get('id'), 'Replica3')
            self.assertFalse(replica_share_2['share_server'])
            self.assertTrue(
                expected_share_keys.issubset(replica_share_2.keys()))
            self.assertIsNone(replica_share_3)

    def test_share_replica_get_exception(self):
        replica = db_utils.create_share_replica(share_id='FAKE_SHARE_ID')

        self.assertRaises(exception.ShareReplicaNotFound,
                          db_api.share_replica_get,
                          self.ctxt, replica['id'])

    def test_share_replica_get_without_share_data(self):
        share = db_utils.create_share()
        replica = db_utils.create_share_replica(
            share_id=share['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE)
        expected_extra_keys = {
            'project_id', 'share_type_id', 'display_name',
            'name', 'share_proto', 'is_public',
            'source_share_group_snapshot_member_id',
        }

        share_replica = db_api.share_replica_get(self.ctxt, replica['id'])

        self.assertIsNotNone(share_replica['replica_state'])
        self.assertEqual(share['id'], share_replica['share_id'])
        self.assertFalse(expected_extra_keys.issubset(share_replica.keys()))

    def test_share_replica_get_with_share_data(self):
        share = db_utils.create_share()
        replica = db_utils.create_share_replica(
            share_id=share['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE)
        expected_extra_keys = {
            'project_id', 'share_type_id', 'display_name',
            'name', 'share_proto', 'is_public',
            'source_share_group_snapshot_member_id',
        }

        share_replica = db_api.share_replica_get(
            self.ctxt, replica['id'], with_share_data=True)

        self.assertIsNotNone(share_replica['replica_state'])
        self.assertEqual(share['id'], share_replica['share_id'])
        self.assertTrue(expected_extra_keys.issubset(share_replica.keys()))

    def test_share_replica_get_with_share_server(self):
        session = db_api.get_session()
        share_server = db_utils.create_share_server()
        share = db_utils.create_share()
        replica = db_utils.create_share_replica(
            share_id=share['id'],
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_server_id=share_server['id']
        )
        expected_extra_keys = {
            'backend_details', 'host', 'id',
            'share_network_subnet_ids', 'status',
        }
        with session.begin():
            share_replica = db_api.share_replica_get(
                self.ctxt, replica['id'], with_share_server=True,
                session=session)

            self.assertIsNotNone(share_replica['replica_state'])
            self.assertEqual(
                share_server['id'], share_replica['share_server_id'])
            self.assertTrue(expected_extra_keys.issubset(
                share_replica['share_server'].keys()))

    def test_share_replica_update(self):
        share = db_utils.create_share()
        replica = db_utils.create_share_replica(
            share_id=share['id'], replica_state=constants.REPLICA_STATE_ACTIVE)

        updated_replica = db_api.share_replica_update(
            self.ctxt, replica['id'],
            {'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC})

        self.assertEqual(constants.REPLICA_STATE_OUT_OF_SYNC,
                         updated_replica['replica_state'])

    def test_share_replica_delete(self):
        share = db_utils.create_share()
        share = db_api.share_get(self.ctxt, share['id'])
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value='reservation'))
        self.mock_object(quota.QUOTAS, 'commit')
        replica = db_utils.create_share_replica(
            share_id=share['id'], replica_state=constants.REPLICA_STATE_ACTIVE)

        self.assertEqual(1, len(
            db_api.share_replicas_get_all_by_share(self.ctxt, share['id'])))

        db_api.share_replica_delete(self.ctxt, replica['id'])

        self.assertEqual(
            [], db_api.share_replicas_get_all_by_share(self.ctxt, share['id']))
        share_type_id = share['instances'][0].get('share_type_id', None)
        quota.QUOTAS.reserve.assert_called_once_with(
            self.ctxt, project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type_id,
            share_replicas=-1, replica_gigabytes=share['size'])
        quota.QUOTAS.commit.assert_called_once_with(
            self.ctxt, 'reservation', project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type_id)

    @ddt.data(
        (True, {"share_replicas": -1, "replica_gigabytes": 0}, 'active'),
        (False, {"shares": -1, "gigabytes": 0}, None),
        (False, {"shares": -1, "gigabytes": 0,
                 "share_replicas": -1, "replica_gigabytes": 0}, 'active')
    )
    @ddt.unpack
    def test_share_instance_delete_quota_error(self, is_replica, deltas,
                                               replica_state):
        share = db_utils.create_share(replica_state=replica_state)
        share = db_api.share_get(self.ctxt, share['id'])
        instance_id = share['instances'][0]['id']

        if is_replica:
            replica = db_utils.create_share_replica(
                share_id=share['id'],
                replica_state=constants.REPLICA_STATE_ACTIVE)
            instance_id = replica['id']
        reservation = 'fake'
        share_type_id = share['instances'][0]['share_type_id']

        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'commit', mock.Mock(
            side_effect=exception.QuotaError('fake')))
        self.mock_object(quota.QUOTAS, 'rollback')

        # NOTE(silvacarlose): not calling with assertRaises since the
        # _update_share_instance_usages method is not raising an exception
        db_api.share_instance_delete(
            self.ctxt, instance_id, session=None, need_to_update_usages=True)

        quota.QUOTAS.reserve.assert_called_once_with(
            self.ctxt, project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type_id, **deltas)
        quota.QUOTAS.commit.assert_called_once_with(
            self.ctxt, reservation, project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type_id)
        quota.QUOTAS.rollback.assert_called_once_with(
            self.ctxt, reservation, share_type_id=share_type_id)

    def test_share_instance_access_copy(self):
        share = db_utils.create_share()
        rules = []
        for i in range(0, 5):
            rules.append(db_utils.create_access(share_id=share['id']))

        instance = db_utils.create_share_instance(share_id=share['id'])

        share_access_rules = db_api.share_instance_access_copy(
            self.ctxt, share['id'], instance['id'])
        share_access_rule_ids = [a['id'] for a in share_access_rules]

        self.assertEqual(5, len(share_access_rules))
        for rule_id in share_access_rule_ids:
            self.assertIsNotNone(
                db_api.share_instance_access_get(
                    self.ctxt, rule_id, instance['id']))

    def test_share_soft_delete(self):
        share = db_utils.create_share()
        db_api.share_soft_delete(self.ctxt, share['id'])
        share = db_api.share_get(self.ctxt, share['id'])

        self.assertEqual(share['is_soft_deleted'], True)

    def test_share_restore(self):
        share = db_utils.create_share(is_soft_deleted=True)
        db_api.share_restore(self.ctxt, share['id'])
        share = db_api.share_get(self.ctxt, share['id'])

        self.assertEqual(share['is_soft_deleted'], False)

    def test_share_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}

        share_1 = db_utils.create_share(size=1)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            metadata, db_api.share_metadata_get(
                self.ctxt, share_id=share_1['id']))

    def test_share_metadata_get_item(self):
        metadata = {'a': 'b', 'c': 'd'}
        key = 'a'
        shouldbe = {'a': 'b'}
        share_1 = db_utils.create_share(size=1)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            shouldbe, db_api.share_metadata_get_item(
                self.ctxt, share_id=share_1['id'],
                key=key))

    def test_share_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        share_1 = db_utils.create_share(size=1)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata1, delete=False)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata2, delete=False)
        self.assertEqual(
            should_be, db_api.share_metadata_get(
                self.ctxt, share_id=share_1['id']))

    def test_share_metadata_update_item(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3'}
        should_be = {'a': '3', 'c': '2'}
        share_1 = db_utils.create_share(size=1)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata1, delete=False)
        db_api.share_metadata_update_item(
            self.ctxt, share_id=share_1['id'],
            item=metadata2)
        self.assertEqual(
            should_be, db_api.share_metadata_get(
                self.ctxt, share_id=share_1['id']))

    def test_share_metadata_delete(self):
        key = 'a'
        metadata = {'a': '1', 'c': '2'}
        should_be = {'c': '2'}
        share_1 = db_utils.create_share(size=1)
        db_api.share_metadata_update(
            self.ctxt, share_id=share_1['id'],
            metadata=metadata, delete=False)
        db_api.share_metadata_delete(
            self.ctxt, share_id=share_1['id'],
            key=key)
        self.assertEqual(
            should_be, db_api.share_metadata_get(
                self.ctxt, share_id=share_1['id']))


@ddt.ddt
class ShareGroupDatabaseAPITestCase(test.TestCase):
    def setUp(self):
        """Run before each test."""
        super(ShareGroupDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def test_share_group_create_with_share_type(self):
        fake_share_types = ["fake_share_type"]
        share_group = db_utils.create_share_group(share_types=fake_share_types)
        share_group = db_api.share_group_get(self.ctxt, share_group['id'])

        self.assertEqual(1, len(share_group['share_types']))

    def test_share_group_get(self):
        share_group = db_utils.create_share_group()

        self.assertDictEqual(
            dict(share_group),
            dict(db_api.share_group_get(self.ctxt, share_group['id'])))

    def test_count_share_groups_in_share_network(self):
        share_network = db_utils.create_share_network()
        db_utils.create_share_group()
        db_utils.create_share_group(share_network_id=share_network['id'])

        count = db_api.count_share_groups_in_share_network(
            self.ctxt, share_network_id=share_network['id'])

        self.assertEqual(1, count)

    def test_share_group_get_all(self):
        expected_share_group = db_utils.create_share_group()

        share_groups = db_api.share_group_get_all(self.ctxt, detailed=False)

        self.assertEqual(1, len(share_groups))
        share_group = share_groups[0]
        self.assertEqual(2, len(dict(share_group).keys()))
        self.assertEqual(expected_share_group['id'], share_group['id'])
        self.assertEqual(expected_share_group['name'], share_group['name'])

    def test_share_group_get_all_with_detail(self):
        expected_share_group = db_utils.create_share_group()

        share_groups = db_api.share_group_get_all(self.ctxt, detailed=True)

        self.assertEqual(1, len(share_groups))
        self.assertDictEqual(dict(expected_share_group), dict(share_groups[0]))

    def test_share_group_get_all_by_host(self):
        fake_host = 'my_fake_host'
        expected_share_group = db_utils.create_share_group(host=fake_host)
        db_utils.create_share_group()

        share_groups = db_api.share_group_get_all_by_host(
            self.ctxt, fake_host, detailed=False)

        self.assertEqual(1, len(share_groups))
        share_group = share_groups[0]
        self.assertEqual(2, len(dict(share_group).keys()))
        self.assertEqual(expected_share_group['id'], share_group['id'])
        self.assertEqual(expected_share_group['name'], share_group['name'])

    def test_share_group_get_all_by_host_with_details(self):
        fake_host = 'my_fake_host'
        expected_share_group = db_utils.create_share_group(host=fake_host)
        db_utils.create_share_group()

        share_groups = db_api.share_group_get_all_by_host(
            self.ctxt, fake_host, detailed=True)

        self.assertEqual(1, len(share_groups))
        share_group = share_groups[0]
        self.assertDictEqual(dict(expected_share_group), dict(share_group))
        self.assertEqual(fake_host, share_group['host'])

    def test_share_group_get_all_by_project(self):
        fake_project = 'fake_project'
        expected_group = db_utils.create_share_group(
            project_id=fake_project)
        db_utils.create_share_group()

        groups = db_api.share_group_get_all_by_project(self.ctxt,
                                                       fake_project,
                                                       detailed=False)

        self.assertEqual(1, len(groups))
        group = groups[0]
        self.assertEqual(2, len(dict(group).keys()))
        self.assertEqual(expected_group['id'], group['id'])
        self.assertEqual(expected_group['name'], group['name'])

    def test_share_group_get_all_by_share_server(self):
        fake_server = 123
        expected_group = db_utils.create_share_group(
            share_server_id=fake_server)
        db_utils.create_share_group()

        groups = db_api.share_group_get_all_by_share_server(self.ctxt,
                                                            fake_server)

        self.assertEqual(1, len(groups))
        group = groups[0]
        self.assertEqual(expected_group['id'], group['id'])
        self.assertEqual(expected_group['name'], group['name'])

    def test_share_group_get_all_by_project_with_details(self):
        fake_project = 'fake_project'
        expected_group = db_utils.create_share_group(
            project_id=fake_project)
        db_utils.create_share_group()

        groups = db_api.share_group_get_all_by_project(self.ctxt,
                                                       fake_project,
                                                       detailed=True)

        self.assertEqual(1, len(groups))
        group = groups[0]
        self.assertDictEqual(dict(expected_group), dict(group))
        self.assertEqual(fake_project, group['project_id'])

    @ddt.data(({'name': 'fo'}, 0), ({'description': 'd'}, 0),
              ({'name': 'foo', 'description': 'd'}, 0),
              ({'name': 'foo'}, 1), ({'description': 'ds'}, 1),
              ({'name~': 'foo', 'description~': 'ds'}, 2),
              ({'name': 'foo', 'description~': 'ds'}, 1),
              ({'name~': 'foo', 'description': 'ds'}, 1))
    @ddt.unpack
    def test_share_group_get_all_by_name_and_description(
            self, search_opts, group_number):
        db_utils.create_share_group(name='fo1', description='d1')
        expected_group1 = db_utils.create_share_group(name='foo',
                                                      description='ds')
        expected_group2 = db_utils.create_share_group(name='foo1',
                                                      description='ds2')

        groups = db_api.share_group_get_all(
            self.ctxt, detailed=True,
            filters=search_opts)

        self.assertEqual(group_number, len(groups))
        if group_number == 1:
            self.assertDictEqual(dict(expected_group1), dict(groups[0]))
        elif group_number == 2:
            self.assertDictEqual(dict(expected_group1), dict(groups[1]))
            self.assertDictEqual(dict(expected_group2), dict(groups[0]))

    def test_share_group_update(self):
        fake_name = "my_fake_name"
        expected_group = db_utils.create_share_group()
        expected_group['name'] = fake_name

        db_api.share_group_update(self.ctxt,
                                  expected_group['id'],
                                  {'name': fake_name})

        group = db_api.share_group_get(self.ctxt, expected_group['id'])
        self.assertEqual(fake_name, group['name'])

    def test_share_group_destroy(self):
        group = db_utils.create_share_group()
        db_api.share_group_get(self.ctxt, group['id'])

        db_api.share_group_destroy(self.ctxt, group['id'])

        self.assertRaises(exception.NotFound, db_api.share_group_get,
                          self.ctxt, group['id'])

    def test_count_shares_in_share_group(self):
        sg = db_utils.create_share_group()
        db_utils.create_share(share_group_id=sg['id'])
        db_utils.create_share()

        count = db_api.count_shares_in_share_group(self.ctxt, sg['id'])

        self.assertEqual(1, count)

    def test_count_sg_snapshots_in_share_group(self):
        sg = db_utils.create_share_group()
        db_utils.create_share_group_snapshot(sg['id'])
        db_utils.create_share_group_snapshot(sg['id'])

        count = db_api.count_share_group_snapshots_in_share_group(
            self.ctxt, sg['id'])

        self.assertEqual(2, count)

    def test_share_group_snapshot_get(self):
        sg = db_utils.create_share_group()
        sg_snap = dict(db_utils.create_share_group_snapshot(sg['id']))
        sg_snap_source_group = sg_snap.pop('share_group', {})
        get_sg_snap = dict(
            db_api.share_group_snapshot_get(self.ctxt, sg_snap['id']))
        get_sg_snap_source_group = get_sg_snap.pop('share_group', {})

        self.assertDictEqual(
            dict(sg_snap_source_group), dict(get_sg_snap_source_group))
        self.assertDictEqual(sg_snap, get_sg_snap)

    def test_share_group_snapshot_get_all(self):
        sg = db_utils.create_share_group()
        expected_sg_snap = db_utils.create_share_group_snapshot(sg['id'])

        snaps = db_api.share_group_snapshot_get_all(self.ctxt, detailed=False)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertEqual(2, len(dict(snap).keys()))
        self.assertEqual(expected_sg_snap['id'], snap['id'])
        self.assertEqual(expected_sg_snap['name'], snap['name'])

    def test_share_group_snapshot_get_all_with_detail(self):
        sg = db_utils.create_share_group()
        expected_sg_snap = dict(db_utils.create_share_group_snapshot(sg['id']))
        sg_snap_source_group = expected_sg_snap.pop('share_group', {})

        snaps = db_api.share_group_snapshot_get_all(self.ctxt, detailed=True)

        self.assertEqual(1, len(snaps))
        actual_sg_snap = dict(snaps[0])
        get_sg_snap_source = actual_sg_snap.pop('share_group', {})
        self.assertDictEqual(
            dict(sg_snap_source_group), dict(get_sg_snap_source))
        self.assertDictEqual(expected_sg_snap, actual_sg_snap)

    def test_share_group_snapshot_get_all_by_project(self):
        fake_project = uuidutils.generate_uuid()
        sg = db_utils.create_share_group()
        expected_sg_snap = db_utils.create_share_group_snapshot(
            sg['id'], project_id=fake_project)

        snaps = db_api.share_group_snapshot_get_all_by_project(
            self.ctxt, fake_project, detailed=False)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertEqual(2, len(dict(snap).keys()))
        self.assertEqual(expected_sg_snap['id'], snap['id'])
        self.assertEqual(expected_sg_snap['name'], snap['name'])

    def test_share_group_snapshot_get_all_by_project_with_details(self):
        fake_project = uuidutils.generate_uuid()
        sg = db_utils.create_share_group()
        expected_sg_snap = dict(db_utils.create_share_group_snapshot(
            sg['id'], project_id=fake_project))
        sg_snap_source_group = expected_sg_snap.pop(
            'share_group', {})

        snaps = db_api.share_group_snapshot_get_all_by_project(
            self.ctxt, fake_project, detailed=True)

        self.assertEqual(1, len(snaps))
        actual_snap = dict(snaps[0])
        get_sg_snap_source = actual_snap.pop('share_group', {})
        self.assertDictEqual(
            dict(sg_snap_source_group), dict(get_sg_snap_source))
        self.assertEqual(expected_sg_snap, actual_snap)
        self.assertEqual(fake_project, actual_snap['project_id'])

    def test_share_group_snapshot_update(self):
        fake_name = "my_fake_name"
        sg = db_utils.create_share_group()
        expected_sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        expected_sg_snap['name'] = fake_name

        db_api.share_group_snapshot_update(
            self.ctxt, expected_sg_snap['id'], {'name': fake_name})

        sg_snap = db_api.share_group_snapshot_get(
            self.ctxt, expected_sg_snap['id'])
        self.assertEqual(fake_name, sg_snap['name'])

    def test_share_group_snapshot_destroy(self):
        sg = db_utils.create_share_group()
        sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        db_api.share_group_snapshot_get(self.ctxt, sg_snap['id'])

        db_api.share_group_snapshot_destroy(self.ctxt, sg_snap['id'])

        self.assertRaises(
            exception.NotFound,
            db_api.share_group_snapshot_get, self.ctxt, sg_snap['id'])

    def test_share_group_snapshot_members_get_all(self):
        sg = db_utils.create_share_group()
        share = db_utils.create_share(share_group_id=sg['id'])
        si = db_utils.create_share_instance(share_id=share['id'])
        sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        expected_member = dict(db_utils.create_share_group_snapshot_member(
            sg_snap['id'], share_instance_id=si['id']))
        sg_snap_source_member = expected_member.pop(
            'share_group_snapshot', {})
        sg_snap_source_member = expected_member.pop('share_instance', {})

        members = db_api.share_group_snapshot_members_get_all(
            self.ctxt, sg_snap['id'])

        self.assertEqual(1, len(members))
        member = dict(members[0])
        get_sg_snap_source_member = member.pop(
            'share_group_snapshot', {})
        get_sg_snap_source_member = member.pop('share_instance', {})
        self.assertDictEqual(dict(
            sg_snap_source_member), dict(get_sg_snap_source_member))
        self.assertDictEqual(expected_member, member)

    def test_count_share_group_snapshot_members_in_share(self):
        sg = db_utils.create_share_group()
        share = db_utils.create_share(share_group_id=sg['id'])
        si = db_utils.create_share_instance(share_id=share['id'])
        share2 = db_utils.create_share(share_group_id=sg['id'])
        si2 = db_utils.create_share_instance(share_id=share2['id'])
        sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        db_utils.create_share_group_snapshot_member(
            sg_snap['id'], share_instance_id=si['id'])
        db_utils.create_share_group_snapshot_member(
            sg_snap['id'], share_instance_id=si2['id'])

        count = db_api.count_share_group_snapshot_members_in_share(
            self.ctxt, share['id'])

        self.assertEqual(1, count)

    def test_share_group_snapshot_members_get(self):
        sg = db_utils.create_share_group()
        share = db_utils.create_share(share_group_id=sg['id'])
        si = db_utils.create_share_instance(share_id=share['id'])
        sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        expected_member = dict(db_utils.create_share_group_snapshot_member(
            sg_snap['id'], share_instance_id=si['id']))
        sg_snap_source_member = expected_member.pop('share_group_snapshot', {})
        sg_snap_source_member = expected_member.pop('share_instance', {})

        member = dict(db_api.share_group_snapshot_member_get(
            self.ctxt, expected_member['id']))
        get_sg_snap_source_member = member.pop('share_group_snapshot', {})
        get_sg_snap_source_member = member.pop('share_instance', {})

        self.assertDictEqual(dict(
            sg_snap_source_member), dict(get_sg_snap_source_member))
        self.assertDictEqual(expected_member, member)

    def test_share_group_snapshot_members_get_not_found(self):
        self.assertRaises(
            exception.ShareGroupSnapshotMemberNotFound,
            db_api.share_group_snapshot_member_get, self.ctxt, 'fake_id')

    def test_share_group_snapshot_member_update(self):
        sg = db_utils.create_share_group()
        share = db_utils.create_share(share_group_id=sg['id'])
        si = db_utils.create_share_instance(share_id=share['id'])
        sg_snap = db_utils.create_share_group_snapshot(sg['id'])
        expected_member = db_utils.create_share_group_snapshot_member(
            sg_snap['id'], share_instance_id=si['id'])

        db_api.share_group_snapshot_member_update(
            self.ctxt, expected_member['id'],
            {'status': constants.STATUS_AVAILABLE})

        member = db_api.share_group_snapshot_member_get(
            self.ctxt, expected_member['id'])
        self.assertEqual(constants.STATUS_AVAILABLE, member['status'])


@ddt.ddt
class ShareGroupTypeAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareGroupTypeAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(
            user_id='user_id', project_id='project_id', is_admin=True)

    @ddt.data(True, False)
    def test_share_type_destroy_in_use(self, used_by_groups):
        share_type_1 = db_utils.create_share_type(name='fike')
        share_type_2 = db_utils.create_share_type(name='bowman')
        share_group_type_1 = db_utils.create_share_group_type(
            name='orange', is_public=False, share_types=[share_type_1['id']],
            group_specs={'dabo': 'allin', 'cadence': 'count'},
            override_defaults=True)
        db_api.share_group_type_access_add(self.ctxt,
                                           share_group_type_1['id'],
                                           "2018ndaetfigovnsaslcahfavmrpions")
        db_api.share_group_type_access_add(self.ctxt,
                                           share_group_type_1['id'],
                                           "2016ndaetfigovnsaslcahfavmrpions")
        share_group_type_2 = db_utils.create_share_group_type(
            name='regalia', share_types=[share_type_2['id']])
        if used_by_groups:
            share_group_1 = db_utils.create_share_group(
                share_group_type_id=share_group_type_1['id'],
                share_types=[share_type_1['id']])
            share_group_2 = db_utils.create_share_group(
                share_group_type_id=share_group_type_2['id'],
                share_types=[share_type_2['id']])
            self.assertRaises(exception.ShareGroupTypeInUse,
                              db_api.share_group_type_destroy,
                              self.ctxt, share_group_type_1['id'])
            self.assertRaises(exception.ShareGroupTypeInUse,
                              db_api.share_group_type_destroy,
                              self.ctxt, share_group_type_2['id'])
            # Cleanup share groups
            db_api.share_group_destroy(self.ctxt, share_group_1['id'])
            db_api.share_group_destroy(self.ctxt, share_group_2['id'])

        # Let's cleanup share_group_type_1 and verify it is gone
        self.assertIsNone(db_api.share_group_type_destroy(
            self.ctxt, share_group_type_1['id']))
        self.assertDictEqual(
            {}, db_api.share_group_type_specs_get(
                self.ctxt, share_group_type_1['id']))
        self.assertRaises(exception.ShareGroupTypeNotFound,
                          db_api.share_group_type_access_get_all,
                          self.ctxt, share_group_type_1['id'])
        self.assertRaises(exception.ShareGroupTypeNotFound,
                          db_api.share_group_type_get,
                          self.ctxt, share_group_type_1['id'])

        # share_group_type_2 must still be around
        self.assertEqual(share_group_type_2['id'],
                         db_api.share_group_type_get(
                             self.ctxt, share_group_type_2['id'])['id'])


@ddt.ddt
class ShareSnapshotDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareSnapshotDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

        self.share_instances = [
            db_utils.create_share_instance(
                status=constants.STATUS_REPLICATION_CHANGE,
                share_id='fake_share_id_1'),
            db_utils.create_share_instance(
                status=constants.STATUS_AVAILABLE,
                share_id='fake_share_id_1'),
            db_utils.create_share_instance(
                status=constants.STATUS_ERROR_DELETING,
                share_id='fake_share_id_2'),
            db_utils.create_share_instance(
                status=constants.STATUS_MANAGING,
                share_id='fake_share_id_2'),
        ]
        self.share_1 = db_utils.create_share(
            id='fake_share_id_1', instances=self.share_instances[0:2])
        self.share_2 = db_utils.create_share(
            id='fake_share_id_2', instances=self.share_instances[2:-1])
        self.snapshot_instances = [
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_1',
                status=constants.STATUS_CREATING,
                share_instance_id=self.share_instances[0]['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_1',
                status=constants.STATUS_ERROR,
                share_instance_id=self.share_instances[1]['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_1',
                status=constants.STATUS_DELETING,
                share_instance_id=self.share_instances[2]['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_2',
                status=constants.STATUS_AVAILABLE,
                id='fake_snapshot_instance_id',
                provider_location='hogsmeade:snapshot1',
                progress='87%',
                share_instance_id=self.share_instances[3]['id']),
        ]
        self.snapshot_1 = db_utils.create_snapshot(
            id='fake_snapshot_id_1', share_id=self.share_1['id'],
            instances=self.snapshot_instances[0:3])
        self.snapshot_2 = db_utils.create_snapshot(
            id='fake_snapshot_id_2', share_id=self.share_2['id'],
            instances=self.snapshot_instances[3:4], metadata={'foo': 'bar'})

        self.snapshot_instance_export_locations = [
            db_utils.create_snapshot_instance_export_locations(
                self.snapshot_instances[0].id,
                path='1.1.1.1:/fake_path',
                is_admin_only=True),
            db_utils.create_snapshot_instance_export_locations(
                self.snapshot_instances[1].id,
                path='2.2.2.2:/fake_path',
                is_admin_only=True),
            db_utils.create_snapshot_instance_export_locations(
                self.snapshot_instances[2].id,
                path='3.3.3.3:/fake_path',
                is_admin_only=True),
            db_utils.create_snapshot_instance_export_locations(
                self.snapshot_instances[3].id,
                path='4.4.4.4:/fake_path',
                is_admin_only=True)
        ]

    def test_create(self):
        share = db_utils.create_share(size=1)
        values = {
            'share_id': share['id'],
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_size': share['size'],
            'display_name': 'fake',
            'display_description': 'fake',
            'share_proto': share['share_proto']
        }

        actual_result = db_api.share_snapshot_create(
            self.ctxt, values, create_snapshot_instance=True)

        self.assertEqual(1, len(actual_result.instances))
        self.assertSubDictMatch(values, actual_result.to_dict())

    @ddt.data(
        ({'with_count': True}, 3, 3),
        ({'with_count': True, 'limit': 2}, 3, 2)
    )
    @ddt.unpack
    def test_share_snapshot_get_all_with_count(self, filters,
                                               amount_of_share_snapshots,
                                               expected_share_snapshots_len):
        share = db_utils.create_share(size=1)
        values = {
            'share_id': share['id'],
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_size': share['size'],
            'display_description': 'fake_count_test',
            'share_proto': share['share_proto'],
        }

        # consider only shares created in this function
        filters.update({'share_id': share['id']})

        for i in range(amount_of_share_snapshots):
            tmp_values = copy.deepcopy(values)
            tmp_values['display_name'] = 'fake_name_%s' % str(i)
            db_api.share_snapshot_create(self.ctxt, tmp_values)

        limit = filters.get('limit')
        count, share_snapshots = db_api.share_snapshot_get_all_with_count(
            self.ctxt, filters=filters, limit=limit)

        self.assertEqual(count, amount_of_share_snapshots)
        self.assertEqual(expected_share_snapshots_len, len(share_snapshots))

    def test_share_snapshot_get_all_with_filters_some(self):
        expected_status = constants.STATUS_AVAILABLE
        filters = {
            'status': expected_status,
            'metadata': {'foo': 'bar'}
        }
        snapshots = db_api.share_snapshot_get_all(
            self.ctxt, filters=filters)

        for snapshot in snapshots:
            s = snapshot.get('share_snapshot_metadata')
            for k, v in filters['metadata'].items():
                filter_meta_key = k
                filter_meta_val = v
            self.assertEqual('fake_snapshot_id_2', snapshot['id'])
            self.assertEqual(snapshot['status'], filters['status'])
            self.assertEqual(s[0]['key'], filter_meta_key)
            self.assertEqual(s[0]['value'], filter_meta_val)

        self.assertEqual(1, len(snapshots))

    def test_share_snapshot_get_latest_for_share(self):

        share = db_utils.create_share(size=1)
        values = {
            'share_id': share['id'],
            'size': share['size'],
            'user_id': share['user_id'],
            'project_id': share['project_id'],
            'status': constants.STATUS_CREATING,
            'progress': '0%',
            'share_size': share['size'],
            'display_description': 'fake',
            'share_proto': share['share_proto'],
        }
        values1 = copy.deepcopy(values)
        values1['display_name'] = 'snap1'
        db_api.share_snapshot_create(self.ctxt, values1)
        values2 = copy.deepcopy(values)
        values2['display_name'] = 'snap2'
        db_api.share_snapshot_create(self.ctxt, values2)
        values3 = copy.deepcopy(values)
        values3['display_name'] = 'snap3'
        db_api.share_snapshot_create(self.ctxt, values3)

        result = db_api.share_snapshot_get_latest_for_share(self.ctxt,
                                                            share['id'])

        self.assertSubDictMatch(values3, result.to_dict())

    def test_get_instance(self):
        snapshot = db_utils.create_snapshot(with_share=True)

        instance = db_api.share_snapshot_instance_get(
            self.ctxt, snapshot.instance['id'], with_share_data=True)
        instance_dict = instance.to_dict()

        self.assertTrue(hasattr(instance, 'name'))
        self.assertTrue(hasattr(instance, 'share_name'))
        self.assertTrue(hasattr(instance, 'share_id'))
        self.assertIn('name', instance_dict)
        self.assertIn('share_name', instance_dict)

    @ddt.data(None, constants.STATUS_ERROR)
    def test_share_snapshot_instance_get_all_with_filters_some(self, status):
        expected_status = status or (constants.STATUS_CREATING,
                                     constants.STATUS_DELETING)
        expected_number = 1 if status else 3
        filters = {
            'snapshot_ids': 'fake_snapshot_id_1',
            'statuses': expected_status
        }
        instances = db_api.share_snapshot_instance_get_all_with_filters(
            self.ctxt, filters)

        for instance in instances:
            self.assertEqual('fake_snapshot_id_1', instance['snapshot_id'])
            self.assertIn(instance['status'], filters['statuses'])

        self.assertEqual(expected_number, len(instances))

    def test_share_snapshot_instance_get_all_with_filters_all_filters(self):
        filters = {
            'snapshot_ids': 'fake_snapshot_id_2',
            'instance_ids': 'fake_snapshot_instance_id',
            'statuses': constants.STATUS_AVAILABLE,
            'share_instance_ids': self.share_instances[3]['id'],
        }
        instances = db_api.share_snapshot_instance_get_all_with_filters(
            self.ctxt, filters, with_share_data=True)
        self.assertEqual(1, len(instances))
        self.assertEqual('fake_snapshot_instance_id', instances[0]['id'])
        self.assertEqual(
            self.share_2['id'], instances[0]['share_instance']['share_id'])

    def test_share_snapshot_instance_get_all_with_filters_wrong_filters(self):
        filters = {
            'some_key': 'some_value',
            'some_other_key': 'some_other_value',
        }
        instances = db_api.share_snapshot_instance_get_all_with_filters(
            self.ctxt, filters)
        self.assertEqual(6, len(instances))

    def test_share_snapshot_instance_create(self):
        snapshot = db_utils.create_snapshot(with_share=True)
        share = snapshot['share']
        share_instance = db_utils.create_share_instance(share_id=share['id'])
        values = {
            'snapshot_id': snapshot['id'],
            'share_instance_id': share_instance['id'],
            'status': constants.STATUS_MANAGING,
            'progress': '88%',
            'provider_location': 'whomping_willow',
        }

        actual_result = db_api.share_snapshot_instance_create(
            self.ctxt, snapshot['id'], values)

        snapshot = db_api.share_snapshot_get(self.ctxt, snapshot['id'])

        self.assertSubDictMatch(values, actual_result.to_dict())
        self.assertEqual(2, len(snapshot['instances']))

    def test_share_snapshot_instance_update(self):
        snapshot = db_utils.create_snapshot(with_share=True)

        values = {
            'snapshot_id': snapshot['id'],
            'status': constants.STATUS_ERROR,
            'progress': '18%',
            'provider_location': 'godrics_hollow',
        }

        actual_result = db_api.share_snapshot_instance_update(
            self.ctxt, snapshot['instance']['id'], values)

        self.assertSubDictMatch(values, actual_result.to_dict())

    @ddt.data(2, 1)
    def test_share_snapshot_instance_delete(self, instances):
        snapshot = db_utils.create_snapshot(with_share=True)
        first_instance_id = snapshot['instance']['id']
        if instances > 1:
            instance = db_utils.create_snapshot_instance(
                snapshot['id'],
                share_instance_id=snapshot['share']['instance']['id'])
        else:
            instance = snapshot['instance']

        retval = db_api.share_snapshot_instance_delete(
            self.ctxt, instance['id'])

        self.assertIsNone(retval)
        if instances == 1:
            self.assertRaises(exception.ShareSnapshotNotFound,
                              db_api.share_snapshot_get,
                              self.ctxt, snapshot['id'])
        else:
            snapshot = db_api.share_snapshot_get(self.ctxt, snapshot['id'])
            self.assertEqual(1, len(snapshot['instances']))
            self.assertEqual(first_instance_id, snapshot['instance']['id'])

    def test_share_snapshot_access_create(self):
        values = {
            'share_snapshot_id': self.snapshot_1['id'],
        }
        actual_result = db_api.share_snapshot_access_create(self.ctxt,
                                                            values)

        self.assertSubDictMatch(values, actual_result.to_dict())

    def test_share_snapshot_instance_access_get_all(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        session = db_api.get_session()
        values = {'share_snapshot_instance_id': self.snapshot_instances[0].id,
                  'access_id': access['id']}

        rules = db_api.share_snapshot_instance_access_get_all(
            self.ctxt, access['id'], session)

        self.assertSubDictMatch(values, rules[0].to_dict())

    def test_share_snapshot_access_get(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        values = {'share_snapshot_id': self.snapshot_1['id']}

        actual_value = db_api.share_snapshot_access_get(
            self.ctxt, access['id'])

        self.assertSubDictMatch(values, actual_value.to_dict())

    def test_share_snapshot_access_get_all_for_share_snapshot(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        values = {'access_type': access['access_type'],
                  'access_to': access['access_to'],
                  'share_snapshot_id': self.snapshot_1['id']}

        actual_value = db_api.share_snapshot_access_get_all_for_share_snapshot(
            self.ctxt, self.snapshot_1['id'], {})

        self.assertSubDictMatch(values, actual_value[0].to_dict())

    @ddt.data({'existing': {'access_type': 'cephx', 'access_to': 'alice'},
               'new': {'access_type': 'user', 'access_to': 'alice'},
               'result': False},
              {'existing': {'access_type': 'user', 'access_to': 'bob'},
               'new': {'access_type': 'user', 'access_to': 'bob'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.0.0.10/32'},
               'new': {'access_type': 'ip', 'access_to': '10.0.0.10'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.10.0.11'},
               'new': {'access_type': 'ip', 'access_to': '10.10.0.11'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': 'fd21::11'},
               'new': {'access_type': 'ip', 'access_to': 'fd21::11'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': 'fd21::10'},
               'new': {'access_type': 'ip', 'access_to': 'fd21::10/128'},
               'result': True},
              {'existing': {'access_type': 'ip', 'access_to': '10.10.0.0/22'},
               'new': {'access_type': 'ip', 'access_to': '10.10.0.0/24'},
               'result': False},
              {'existing': {'access_type': 'ip', 'access_to': '2620:52::/48'},
               'new': {'access_type': 'ip',
                       'access_to': '2620:52:0:13b8::/64'},
               'result': False})
    @ddt.unpack
    def test_share_snapshot_check_for_existing_access(self, existing, new,
                                                      result):
        db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'],
            access_type=existing['access_type'],
            access_to=existing['access_to'])

        rule_exists = db_api.share_snapshot_check_for_existing_access(
            self.ctxt, self.snapshot_1['id'], new['access_type'],
            new['access_to'])

        self.assertEqual(result, rule_exists)

    def test_share_snapshot_access_get_all_for_snapshot_instance(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        values = {'access_type': access['access_type'],
                  'access_to': access['access_to'],
                  'share_snapshot_id': self.snapshot_1['id']}

        out = db_api.share_snapshot_access_get_all_for_snapshot_instance(
            self.ctxt, self.snapshot_instances[0].id)

        self.assertSubDictMatch(values, out[0].to_dict())

    def test_share_snapshot_instance_access_update_state(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        values = {'state': constants.STATUS_ACTIVE,
                  'access_id': access['id'],
                  'share_snapshot_instance_id': self.snapshot_instances[0].id}

        actual_result = db_api.share_snapshot_instance_access_update(
            self.ctxt, access['id'], self.snapshot_1.instance['id'],
            {'state': constants.STATUS_ACTIVE})

        self.assertSubDictMatch(values, actual_result.to_dict())
        self.assertIsNotNone(actual_result['updated_at'])
        time_now = timeutils.utcnow()
        self.assertTrue(actual_result['updated_at'] < time_now)

    def test_share_snapshot_instance_access_get(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])
        values = {'access_id': access['id'],
                  'share_snapshot_instance_id': self.snapshot_instances[0].id}

        actual_result = db_api.share_snapshot_instance_access_get(
            self.ctxt, access['id'], self.snapshot_instances[0].id)

        self.assertSubDictMatch(values, actual_result.to_dict())

    def test_share_snapshot_instance_access_delete(self):
        access = db_utils.create_snapshot_access(
            share_snapshot_id=self.snapshot_1['id'])

        db_api.share_snapshot_instance_access_delete(
            self.ctxt, access['id'], self.snapshot_1.instance['id'])

    def test_share_snapshot_instance_export_location_create(self):
        values = {
            'share_snapshot_instance_id': self.snapshot_instances[0].id,
        }

        actual_result = db_api.share_snapshot_instance_export_location_create(
            self.ctxt, values)

        self.assertSubDictMatch(values, actual_result.to_dict())

    def test_share_snapshot_export_locations_get(self):
        out = db_api.share_snapshot_export_locations_get(
            self.ctxt, self.snapshot_1['id'])

        keys = ['share_snapshot_instance_id', 'path', 'is_admin_only']
        for expected, actual in zip(self.snapshot_instance_export_locations,
                                    out):
            [self.assertEqual(expected[k], actual[k]) for k in keys]

    def test_share_snapshot_instance_export_locations_get(self):
        out = db_api.share_snapshot_instance_export_locations_get_all(
            self.ctxt, self.snapshot_instances[0].id)

        keys = ['share_snapshot_instance_id', 'path', 'is_admin_only']
        for key in keys:
            self.assertEqual(self.snapshot_instance_export_locations[0][key],
                             out[0][key])

    def test_share_snapshot_instance_export_locations_update(self):
        snapshot = db_utils.create_snapshot(with_share=True)
        initial_locations = ['fake1/1/', 'fake2/2', 'fake3/3']
        update_locations = ['fake4/4', 'fake2/2', 'fake3/3']

        # add initial locations
        db_api.share_snapshot_instance_export_locations_update(
            self.ctxt, snapshot.instance['id'], initial_locations, False)
        # update locations
        db_api.share_snapshot_instance_export_locations_update(
            self.ctxt, snapshot.instance['id'], update_locations, True)

        get_result = db_api.share_snapshot_instance_export_locations_get_all(
            self.ctxt, snapshot.instance['id'])
        result_locations = [el['path'] for el in get_result]

        self.assertEqual(sorted(result_locations), sorted(update_locations))

    def test_share_snapshot_instance_export_locations_update_wrong_type(self):
        snapshot = db_utils.create_snapshot(with_share=True)
        new_export_locations = [1]

        self.assertRaises(
            exception.ManilaException,
            db_api.share_snapshot_instance_export_locations_update,
            self.ctxt, snapshot.instance['id'], new_export_locations, False)

    def test_share_snapshot_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}

        self.share_1 = db_utils.create_share(size=1)
        self.snapshot_1 = db_utils.create_snapshot(
            share_id=self.share_1['id'])
        db_api.share_snapshot_metadata_update(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            metadata, db_api.share_snapshot_metadata_get(
                self.ctxt, share_snapshot_id=self.snapshot_1['id']))

    def test_share_snapshot_metadata_get_item(self):
        metadata = {'a': 'b', 'c': 'd'}
        key = 'a'
        shouldbe = {'a': 'b'}
        self.share_1 = db_utils.create_share(size=1)
        self.snapshot_1 = db_utils.create_snapshot(
            share_id=self.share_1['id'])
        db_api.share_snapshot_metadata_update(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            shouldbe, db_api.share_snapshot_metadata_get_item(
                self.ctxt, share_snapshot_id=self.snapshot_1['id'],
                key=key))

    def test_share_snapshot_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        self.share_1 = db_utils.create_share(size=1)
        self.snapshot_1 = db_utils.create_snapshot(
            share_id=self.share_1['id'])
        db_api.share_snapshot_metadata_update(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            metadata=metadata1, delete=False)
        db_api.share_snapshot_metadata_update(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            metadata=metadata2, delete=False)
        self.assertEqual(
            should_be, db_api.share_snapshot_metadata_get(
                self.ctxt, share_snapshot_id=self.snapshot_1['id']))

    def test_share_snapshot_metadata_delete(self):
        key = 'a'
        metadata = {'a': '1', 'c': '2'}
        should_be = {'c': '2'}
        self.share_1 = db_utils.create_share(size=1)
        self.snapshot_1 = db_utils.create_snapshot(
            share_id=self.share_1['id'])
        db_api.share_snapshot_metadata_update(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            metadata=metadata, delete=False)
        db_api.share_snapshot_metadata_delete(
            self.ctxt, share_snapshot_id=self.snapshot_1['id'],
            key=key)
        self.assertEqual(
            should_be, db_api.share_snapshot_metadata_get(
                self.ctxt, share_snapshot_id=self.snapshot_1['id']))


class ShareExportLocationsDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareExportLocationsDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def test_update_valid_order(self):
        share = db_utils.create_share()
        initial_locations = ['fake1/1/', 'fake2/2', 'fake3/3']
        update_locations = ['fake4/4', 'fake2/2', 'fake3/3']

        # add initial locations
        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_locations, False)
        # update locations
        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             update_locations, True)
        actual_result = db_api.share_export_locations_get(self.ctxt,
                                                          share['id'])

        # actual result should contain locations in exact same order
        self.assertEqual(actual_result, update_locations)

    def test_update_string(self):
        share = db_utils.create_share()
        initial_location = 'fake1/1/'

        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_location, False)
        actual_result = db_api.share_export_locations_get(self.ctxt,
                                                          share['id'])

        self.assertEqual(actual_result, [initial_location])

    def test_get_admin_export_locations(self):
        ctxt_user = context.RequestContext(
            user_id='fake user', project_id='fake project', is_admin=False)
        share = db_utils.create_share()
        locations = [
            {'path': 'fake1/1/', 'is_admin_only': True},
            {'path': 'fake2/2/', 'is_admin_only': True},
            {'path': 'fake3/3/', 'is_admin_only': True},
        ]

        db_api.share_export_locations_update(
            self.ctxt, share.instance['id'], locations, delete=False)

        user_result = db_api.share_export_locations_get(ctxt_user, share['id'])
        self.assertEqual([], user_result)

        admin_result = db_api.share_export_locations_get(
            self.ctxt, share['id'])
        self.assertEqual(3, len(admin_result))
        for location in locations:
            self.assertIn(location['path'], admin_result)

    def test_get_user_export_locations(self):
        ctxt_user = context.RequestContext(
            user_id='fake user', project_id='fake project', is_admin=False)
        share = db_utils.create_share()
        locations = [
            {'path': 'fake1/1/', 'is_admin_only': False},
            {'path': 'fake2/2/', 'is_admin_only': False},
            {'path': 'fake3/3/', 'is_admin_only': False},
        ]

        db_api.share_export_locations_update(
            self.ctxt, share.instance['id'], locations, delete=False)

        user_result = db_api.share_export_locations_get(ctxt_user, share['id'])
        self.assertEqual(3, len(user_result))
        for location in locations:
            self.assertIn(location['path'], user_result)

        admin_result = db_api.share_export_locations_get(
            self.ctxt, share['id'])
        self.assertEqual(3, len(admin_result))
        for location in locations:
            self.assertIn(location['path'], admin_result)

    def test_get_user_export_locations_old_view(self):
        ctxt_user = context.RequestContext(
            user_id='fake user', project_id='fake project', is_admin=False)
        share = db_utils.create_share()
        locations = ['fake1/1/', 'fake2/2', 'fake3/3']

        db_api.share_export_locations_update(
            self.ctxt, share.instance['id'], locations, delete=False)

        user_result = db_api.share_export_locations_get(ctxt_user, share['id'])
        self.assertEqual(locations, user_result)

        admin_result = db_api.share_export_locations_get(
            self.ctxt, share['id'])
        self.assertEqual(locations, admin_result)


@ddt.ddt
class ShareInstanceExportLocationsMetadataDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        clname = ShareInstanceExportLocationsMetadataDatabaseAPITestCase
        super(clname, self).setUp()
        self.ctxt = context.get_admin_context()
        share_id = 'fake_share_id'
        instances = [
            db_utils.create_share_instance(
                share_id=share_id,
                status=constants.STATUS_AVAILABLE),
            db_utils.create_share_instance(
                share_id=share_id,
                status=constants.STATUS_MIGRATING),
            db_utils.create_share_instance(
                share_id=share_id,
                status=constants.STATUS_MIGRATING_TO),
        ]
        self.share = db_utils.create_share(
            id=share_id,
            instances=instances)
        self.initial_locations = ['/fake/foo/', '/fake/bar', '/fake/quuz']
        self.shown_locations = ['/fake/foo/', '/fake/bar']
        for i in range(0, 3):
            db_api.share_export_locations_update(
                self.ctxt, instances[i]['id'], self.initial_locations[i],
                delete=False)

    def _get_export_location_uuid_by_path(self, path):
        els = db_api.share_export_locations_get_by_share_id(
            self.ctxt, self.share.id)
        export_location_uuid = None
        for el in els:
            if el.path == path:
                export_location_uuid = el.uuid
        self.assertIsNotNone(export_location_uuid)
        return export_location_uuid

    def test_get_export_locations_by_share_id(self):
        els = db_api.share_export_locations_get_by_share_id(
            self.ctxt, self.share.id)
        self.assertEqual(3, len(els))
        for path in self.shown_locations:
            self.assertTrue(any([path in el.path for el in els]))

    def test_get_export_locations_by_share_id_ignore_migration_dest(self):
        els = db_api.share_export_locations_get_by_share_id(
            self.ctxt, self.share.id, ignore_migration_destination=True)
        self.assertEqual(2, len(els))
        for path in self.shown_locations:
            self.assertTrue(any([path in el.path for el in els]))

    def test_get_export_locations_by_share_instance_id(self):
        els = db_api.share_export_locations_get_by_share_instance_id(
            self.ctxt, self.share.instance.id)
        self.assertEqual(1, len(els))
        for path in [self.shown_locations[1]]:
            self.assertTrue(any([path in el.path for el in els]))

    def test_export_location_metadata_update_delete(self):
        export_location_uuid = self._get_export_location_uuid_by_path(
            self.initial_locations[0])
        metadata = {
            'foo_key': 'foo_value',
            'bar_key': 'bar_value',
            'quuz_key': 'quuz_value',
        }

        db_api.export_location_metadata_update(
            self.ctxt, export_location_uuid, metadata, False)

        db_api.export_location_metadata_delete(
            self.ctxt, export_location_uuid, list(metadata.keys())[0:-1])

        result = db_api.export_location_metadata_get(
            self.ctxt, export_location_uuid)

        key = list(metadata.keys())[-1]
        self.assertEqual({key: metadata[key]}, result)

        db_api.export_location_metadata_delete(
            self.ctxt, export_location_uuid)

        result = db_api.export_location_metadata_get(
            self.ctxt, export_location_uuid)
        self.assertEqual({}, result)

    def test_export_location_metadata_update_get(self):

        # Write metadata for target export location
        export_location_uuid = self._get_export_location_uuid_by_path(
            self.initial_locations[0])
        metadata = {'foo_key': 'foo_value', 'bar_key': 'bar_value'}
        db_api.export_location_metadata_update(
            self.ctxt, export_location_uuid, metadata, False)

        # Write metadata for some concurrent export location
        other_export_location_uuid = self._get_export_location_uuid_by_path(
            self.initial_locations[1])
        other_metadata = {'key_from_other_el': 'value_of_key_from_other_el'}
        db_api.export_location_metadata_update(
            self.ctxt, other_export_location_uuid, other_metadata, False)

        result = db_api.export_location_metadata_get(
            self.ctxt, export_location_uuid)

        self.assertEqual(metadata, result)

        updated_metadata = {
            'foo_key': metadata['foo_key'],
            'quuz_key': 'quuz_value',
        }

        db_api.export_location_metadata_update(
            self.ctxt, export_location_uuid, updated_metadata, True)

        result = db_api.export_location_metadata_get(
            self.ctxt, export_location_uuid)

        self.assertEqual(updated_metadata, result)

    @ddt.data(
        ("k", "v"),
        ("k" * 256, "v"),
        ("k", "v" * 1024),
        ("k" * 256, "v" * 1024),
    )
    @ddt.unpack
    def test_set_metadata_with_different_length(self, key, value):
        export_location_uuid = self._get_export_location_uuid_by_path(
            self.initial_locations[1])
        metadata = {key: value}

        db_api.export_location_metadata_update(
            self.ctxt, export_location_uuid, metadata, False)

        result = db_api.export_location_metadata_get(
            self.ctxt, export_location_uuid)

        self.assertEqual(metadata, result)


@ddt.ddt
class DriverPrivateDataDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(DriverPrivateDataDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def _get_driver_test_data(self):
        return uuidutils.generate_uuid()

    @ddt.data({"details": {"foo": "bar", "tee": "too"},
               "valid": {"foo": "bar", "tee": "too"}},
              {"details": {"foo": "bar", "tee": ["test"]},
               "valid": {"foo": "bar", "tee": str(["test"])}})
    @ddt.unpack
    def test_update(self, details, valid):
        test_id = self._get_driver_test_data()

        initial_data = db_api.driver_private_data_get(self.ctxt, test_id)
        db_api.driver_private_data_update(self.ctxt, test_id, details)
        actual_data = db_api.driver_private_data_get(self.ctxt, test_id)

        self.assertEqual({}, initial_data)
        self.assertEqual(valid, actual_data)

    @ddt.data({'with_deleted': True, 'append': False},
              {'with_deleted': True, 'append': True},
              {'with_deleted': False, 'append': False},
              {'with_deleted': False, 'append': True})
    @ddt.unpack
    def test_update_with_more_values(self, with_deleted, append):
        test_id = self._get_driver_test_data()
        details = {"tee": "too"}
        more_details = {"foo": "bar"}
        result = {"tee": "too", "foo": "bar"}

        db_api.driver_private_data_update(self.ctxt, test_id, details)
        if with_deleted:
            db_api.driver_private_data_delete(self.ctxt, test_id)
        if append:
            more_details.update(details)
        if with_deleted and not append:
            result.pop("tee")
        db_api.driver_private_data_update(self.ctxt, test_id, more_details)

        actual_result = db_api.driver_private_data_get(self.ctxt,
                                                       test_id)

        self.assertEqual(result, actual_result)

    @ddt.data(True, False)
    def test_update_with_duplicate(self, with_deleted):
        test_id = self._get_driver_test_data()
        details = {"tee": "too"}

        db_api.driver_private_data_update(self.ctxt, test_id, details)
        if with_deleted:
            db_api.driver_private_data_delete(self.ctxt, test_id)
        db_api.driver_private_data_update(self.ctxt, test_id, details)

        actual_result = db_api.driver_private_data_get(self.ctxt,
                                                       test_id)

        self.assertEqual(details, actual_result)

    def test_update_with_delete_existing(self):
        test_id = self._get_driver_test_data()
        details = {"key1": "val1", "key2": "val2", "key3": "val3"}
        details_update = {"key1": "val1_upd", "key4": "new_val"}

        # Create new details
        db_api.driver_private_data_update(self.ctxt, test_id, details)
        db_api.driver_private_data_update(self.ctxt, test_id,
                                          details_update, delete_existing=True)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_id)

        self.assertEqual(details_update, actual_result)

    def test_get(self):
        test_id = self._get_driver_test_data()
        test_key = "foo"
        test_keys = [test_key, "tee"]
        details = {test_keys[0]: "val", test_keys[1]: "val", "mee": "foo"}
        db_api.driver_private_data_update(self.ctxt, test_id, details)

        actual_result_all = db_api.driver_private_data_get(
            self.ctxt, test_id)
        actual_result_single_key = db_api.driver_private_data_get(
            self.ctxt, test_id, test_key)
        actual_result_list = db_api.driver_private_data_get(
            self.ctxt, test_id, test_keys)

        self.assertEqual(details, actual_result_all)
        self.assertEqual(details[test_key], actual_result_single_key)
        self.assertEqual(dict.fromkeys(test_keys, "val"), actual_result_list)

    def test_delete_single(self):
        test_id = self._get_driver_test_data()
        test_key = "foo"
        details = {test_key: "bar", "tee": "too"}
        valid_result = {"tee": "too"}
        db_api.driver_private_data_update(self.ctxt, test_id, details)

        db_api.driver_private_data_delete(self.ctxt, test_id, test_key)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_id)

        self.assertEqual(valid_result, actual_result)

    def test_delete_all(self):
        test_id = self._get_driver_test_data()
        details = {"foo": "bar", "tee": "too"}
        db_api.driver_private_data_update(self.ctxt, test_id, details)

        db_api.driver_private_data_delete(self.ctxt, test_id)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_id)

        self.assertEqual({}, actual_result)


@ddt.ddt
class ShareNetworkDatabaseAPITestCase(BaseDatabaseAPITestCase):

    def __init__(self, *args, **kwargs):
        super(ShareNetworkDatabaseAPITestCase, self).__init__(*args, **kwargs)
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    def setUp(self):
        super(ShareNetworkDatabaseAPITestCase, self).setUp()
        self.share_nw_dict = {'id': 'fake network id',
                              'project_id': self.fake_context.project_id,
                              'user_id': 'fake_user_id',
                              'name': 'whatever',
                              'description': 'fake description'}

    def test_create_one_network(self):
        result = db_api.share_network_create(self.fake_context,
                                             self.share_nw_dict)

        self._check_fields(expected=self.share_nw_dict, actual=result)
        self.assertEqual(0, len(result['share_instances']))
        self.assertEqual(0, len(result['security_services']))

    def test_create_two_networks_in_different_tenants(self):
        share_nw_dict2 = self.share_nw_dict.copy()
        share_nw_dict2['id'] = None
        share_nw_dict2['project_id'] = 'fake project 2'
        result1 = db_api.share_network_create(self.fake_context,
                                              self.share_nw_dict)
        result2 = db_api.share_network_create(self.fake_context.elevated(),
                                              share_nw_dict2)

        self._check_fields(expected=self.share_nw_dict, actual=result1)
        self._check_fields(expected=share_nw_dict2, actual=result2)

    def test_create_two_networks_in_one_tenant(self):
        share_nw_dict2 = self.share_nw_dict.copy()
        share_nw_dict2['id'] += "suffix"
        result1 = db_api.share_network_create(self.fake_context,
                                              self.share_nw_dict)
        result2 = db_api.share_network_create(self.fake_context,
                                              share_nw_dict2)
        self._check_fields(expected=self.share_nw_dict, actual=result1)
        self._check_fields(expected=share_nw_dict2, actual=result2)

    def test_create_with_duplicated_id(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(db_exception.DBDuplicateEntry,
                          db_api.share_network_create,
                          self.fake_context,
                          self.share_nw_dict)

    def test_get(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self._check_fields(expected=self.share_nw_dict, actual=result)
        self.assertEqual(0, len(result['share_instances']))
        self.assertEqual(0, len(result['security_services']))

    def _create_share_network_for_project(self, project_id):
        ctx = context.RequestContext(user_id='fake user',
                                     project_id=project_id,
                                     is_admin=False)

        share_data = self.share_nw_dict.copy()
        share_data['project_id'] = project_id

        db_api.share_network_create(ctx, share_data)
        return share_data

    def test_get_other_tenant_as_admin(self):
        expected = self._create_share_network_for_project('fake project 2')
        result = db_api.share_network_get(self.fake_context.elevated(),
                                          self.share_nw_dict['id'])

        self._check_fields(expected=expected, actual=result)
        self.assertEqual(0, len(result['share_instances']))
        self.assertEqual(0, len(result['security_services']))

    def test_get_other_tenant(self):
        self._create_share_network_for_project('fake project 2')
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_get,
                          self.fake_context,
                          self.share_nw_dict['id'])

    @ddt.data([{'id': 'fake share id1'}],
              [{'id': 'fake share id1'}, {'id': 'fake share id2'}],)
    def test_get_with_shares(self, shares):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        share_instances = []
        for share in shares:
            share.update({'share_network_id': self.share_nw_dict['id']})
            share_instances.append(
                db_api.share_create(self.fake_context, share).instance
            )

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(shares), len(result['share_instances']))
        for index, share_instance in enumerate(share_instances):
            self.assertEqual(
                share_instance['share_network_id'],
                result['share_instances'][index]['share_network_id']
            )

    @ddt.data([{'id': 'fake security service id1', 'type': 'fake type'}],
              [{'id': 'fake security service id1', 'type': 'fake type'},
               {'id': 'fake security service id2', 'type': 'fake type'}])
    def test_get_with_security_services(self, security_services):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        for service in security_services:
            service.update({'project_id': self.fake_context.project_id})
            db_api.security_service_create(self.fake_context, service)
            db_api.share_network_add_security_service(
                self.fake_context, self.share_nw_dict['id'], service['id'])

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(security_services),
                         len(result['security_services']))

        for index, service in enumerate(security_services):
            self._check_fields(expected=service,
                               actual=result['security_services'][index])

    @ddt.data([{'id': 'fake_id_1', 'availability_zone_id': 'None'}],
              [{'id': 'fake_id_2', 'availability_zone_id': 'None'},
               {'id': 'fake_id_3', 'availability_zone_id': 'fake_az_id'}])
    def test_get_with_subnets(self, subnets):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        for subnet in subnets:
            subnet['share_network_id'] = self.share_nw_dict['id']
            db_api.share_network_subnet_create(self.fake_context, subnet)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(len(subnets),
                         len(result['share_network_subnets']))

        for index, subnet in enumerate(subnets):
            self._check_fields(expected=subnet,
                               actual=result['share_network_subnets'][index])

    def test_get_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_get,
                          self.fake_context,
                          'fake id')

    def test_delete(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_delete(self.fake_context,
                                    self.share_nw_dict['id'])

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_get,
                          self.fake_context,
                          self.share_nw_dict['id'])

    def test_delete_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_delete,
                          self.fake_context,
                          'fake id')

    def test_update(self):
        new_name = 'fake_new_name'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        result_update = db_api.share_network_update(self.fake_context,
                                                    self.share_nw_dict['id'],
                                                    {'name': new_name})
        result_get = db_api.share_network_get(self.fake_context,
                                              self.share_nw_dict['id'])

        self.assertEqual(new_name, result_update['name'])
        self._check_fields(expected=dict(result_update.items()),
                           actual=dict(result_get.items()))

    def test_update_not_found(self):
        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_update,
                          self.fake_context,
                          'fake id',
                          {})

    @ddt.data(1, 2)
    def test_get_all_one_record(self, records_count):
        index = 0
        share_networks = []
        while index < records_count:
            share_network_dict = dict(self.share_nw_dict)
            fake_id = 'fake_id%s' % index
            share_network_dict.update({'id': fake_id,
                                       'project_id': fake_id})
            share_networks.append(share_network_dict)
            db_api.share_network_create(self.fake_context.elevated(),
                                        share_network_dict)
            index += 1

        result = db_api.share_network_get_all(self.fake_context.elevated())

        self.assertEqual(len(share_networks), len(result))
        for index, net in enumerate(share_networks):
            self._check_fields(expected=net, actual=result[index])

    def test_get_all_by_filter_with_project_id(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        share_nw_dict2 = dict(self.share_nw_dict)
        share_nw_dict2['id'] = 'fake share nw id2'
        share_nw_dict2['project_id'] = 'fake project 2'
        new_context = context.RequestContext(user_id='fake user 2',
                                             project_id='fake project 2',
                                             is_admin=False)
        db_api.share_network_create(new_context, share_nw_dict2)

        filters = {'project_id': share_nw_dict2['project_id']}
        result = db_api.share_network_get_all_by_filter(
            self.fake_context.elevated(), filters=filters)

        self.assertEqual(1, len(result))
        self._check_fields(expected=share_nw_dict2, actual=result[0])

    def test_get_all_with_created_since_or_before_filter(self):
        now = timeutils.utcnow()

        share_nw1 = dict(self.share_nw_dict)
        share_nw2 = dict(self.share_nw_dict)
        share_nw3 = dict(self.share_nw_dict)

        share_nw1['created_at'] = (now - datetime.timedelta(seconds=1))
        share_nw2['created_at'] = (now + datetime.timedelta(seconds=1))
        share_nw3['created_at'] = (now + datetime.timedelta(seconds=2))

        share_nw1['id'] = 'fake share nw id1'
        share_nw2['id'] = 'fake share nw id2'
        share_nw3['id'] = 'fake share nw id3'

        db_api.share_network_create(self.fake_context, share_nw1)
        db_api.share_network_create(self.fake_context, share_nw2)
        db_api.share_network_create(self.fake_context, share_nw3)

        filters1 = {'created_before': now}
        filters2 = {'created_since': now}

        result1 = db_api.share_network_get_all_by_filter(
            self.fake_context.elevated(), filters=filters1)
        result2 = db_api.share_network_get_all_by_filter(
            self.fake_context.elevated(), filters=filters2)

        self.assertEqual(1, len(result1))
        self.assertEqual(2, len(result2))

    def test_get_all_by_project(self):
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        share_nw_dict2 = dict(self.share_nw_dict)
        share_nw_dict2['id'] = 'fake share nw id2'
        share_nw_dict2['project_id'] = 'fake project 2'
        new_context = context.RequestContext(user_id='fake user 2',
                                             project_id='fake project 2',
                                             is_admin=False)
        db_api.share_network_create(new_context, share_nw_dict2)

        result = db_api.share_network_get_all_by_project(
            self.fake_context.elevated(),
            share_nw_dict2['project_id'])

        self.assertEqual(1, len(result))
        self._check_fields(expected=share_nw_dict2, actual=result[0])

    def test_add_security_service(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        result = (db_api.model_query(
                  self.fake_context,
                  models.ShareNetworkSecurityServiceAssociation).
                  filter_by(security_service_id=security_dict1['id']).
                  filter_by(share_network_id=self.share_nw_dict['id']).
                  first())

        self.assertIsNotNone(result)

    def test_add_security_service_not_found_01(self):
        security_service_id = 'unknown security service'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.share_network_add_security_service,
                          self.fake_context,
                          self.share_nw_dict['id'],
                          security_service_id)

    def test_add_security_service_not_found_02(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        share_nw_id = 'unknown share network'
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_add_security_service,
                          self.fake_context,
                          share_nw_id,
                          security_dict1['id'])

    def test_add_security_service_association_error_already_associated(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        self.assertRaises(
            exception.ShareNetworkSecurityServiceAssociationError,
            db_api.share_network_add_security_service,
            self.fake_context,
            self.share_nw_dict['id'],
            security_dict1['id'])

    def test_remove_security_service(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)
        db_api.share_network_add_security_service(self.fake_context,
                                                  self.share_nw_dict['id'],
                                                  security_dict1['id'])

        db_api.share_network_remove_security_service(self.fake_context,
                                                     self.share_nw_dict['id'],
                                                     security_dict1['id'])

        result = (db_api.model_query(
                  self.fake_context,
                  models.ShareNetworkSecurityServiceAssociation).
                  filter_by(security_service_id=security_dict1['id']).
                  filter_by(share_network_id=self.share_nw_dict['id']).first())

        self.assertIsNone(result)

        share_nw_ref = db_api.share_network_get(self.fake_context,
                                                self.share_nw_dict['id'])
        self.assertEqual(0, len(share_nw_ref['security_services']))

    def test_remove_security_service_not_found_01(self):
        security_service_id = 'unknown security service'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.share_network_remove_security_service,
                          self.fake_context,
                          self.share_nw_dict['id'],
                          security_service_id)

    def test_remove_security_service_not_found_02(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}
        share_nw_id = 'unknown share network'
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(exception.ShareNetworkNotFound,
                          db_api.share_network_remove_security_service,
                          self.fake_context,
                          share_nw_id,
                          security_dict1['id'])

    def test_remove_security_service_dissociation_error(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)

        self.assertRaises(
            exception.ShareNetworkSecurityServiceDissociationError,
            db_api.share_network_remove_security_service,
            self.fake_context,
            self.share_nw_dict['id'],
            security_dict1['id'])

    def test_security_services_relation(self):
        security_dict1 = {'id': 'fake security service id1',
                          'project_id': self.fake_context.project_id,
                          'type': 'fake type'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.security_service_create(self.fake_context, security_dict1)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(0, len(result['security_services']))

    def test_shares_relation(self):
        share_dict = {'id': 'fake share id1'}

        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_create(self.fake_context, share_dict)

        result = db_api.share_network_get(self.fake_context,
                                          self.share_nw_dict['id'])

        self.assertEqual(0, len(result['share_instances']))

    def test_association_get(self):
        network = db_api.share_network_create(
            self.fake_context, self.share_nw_dict)
        security_service = db_api.security_service_create(
            self.fake_context, security_service_dict)
        network_id = network['id']
        security_service_id = security_service['id']

        db_api.share_network_add_security_service(
            self.fake_context, network_id, security_service_id)
        result = db_api.share_network_security_service_association_get(
            self.fake_context, network_id, security_service_id)

        self.assertEqual(result['share_network_id'], network_id)
        self.assertEqual(result['security_service_id'], security_service_id)

    def test_share_network_update_security_service(self):
        new_sec_service = copy.copy(security_service_dict)
        new_sec_service['id'] = 'fakeid'
        share_network_id = self.share_nw_dict['id']
        db_api.share_network_create(
            self.fake_context, self.share_nw_dict)
        db_api.security_service_create(
            self.fake_context, security_service_dict)
        db_api.security_service_create(self.fake_context, new_sec_service)
        db_api.share_network_add_security_service(
            self.fake_context, share_network_id,
            security_service_dict['id'])
        db_api.share_network_update_security_service(
            self.fake_context, share_network_id, security_service_dict['id'],
            new_sec_service['id'])

        association = db_api.share_network_security_service_association_get(
            self.fake_context, share_network_id, new_sec_service['id'])

        self.assertEqual(association['share_network_id'], share_network_id)
        self.assertEqual(
            association['security_service_id'], new_sec_service['id'])


@ddt.ddt
class ShareNetworkSubnetDatabaseAPITestCase(BaseDatabaseAPITestCase):

    def __init__(self, *args, **kwargs):
        super(ShareNetworkSubnetDatabaseAPITestCase, self).__init__(
            *args, **kwargs)
        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    def setUp(self):
        super(ShareNetworkSubnetDatabaseAPITestCase, self).setUp()
        self.subnet_dict = {'id': 'fake network id',
                            'neutron_net_id': 'fake net id',
                            'neutron_subnet_id': 'fake subnet id',
                            'network_type': 'vlan',
                            'segmentation_id': 1000,
                            'share_network_id': 'fake_id',
                            'cidr': '10.0.0.0/24',
                            'ip_version': 4,
                            'availability_zone_id': None}

    def test_create(self):
        result = db_api.share_network_subnet_create(
            self.fake_context, self.subnet_dict)
        self._check_fields(expected=self.subnet_dict, actual=result)

    def test_create_duplicated_id(self):
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        self.assertRaises(db_exception.DBDuplicateEntry,
                          db_api.share_network_subnet_create,
                          self.fake_context,
                          self.subnet_dict)

    def test_get(self):
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        result = db_api.share_network_subnet_get(self.fake_context,
                                                 self.subnet_dict['id'])
        self._check_fields(expected=self.subnet_dict, actual=result)

    @ddt.data([{'id': 'fake_id_1', 'identifier': 'fake_identifier',
                'host': 'fake_host'}],
              [{'id': 'fake_id_2', 'identifier': 'fake_identifier',
                'host': 'fake_host'},
               {'id': 'fake_id_3', 'identifier': 'fake_identifier',
                'host': 'fake_host'}])
    def test_get_with_share_servers(self, share_servers):
        share_net_subnets = [
            db_api.share_network_subnet_create(
                self.fake_context, self.subnet_dict)]

        for share_server in share_servers:
            share_server['share_network_subnets'] = share_net_subnets
            db_api.share_server_create(self.fake_context, share_server)

        result = db_api.share_network_subnet_get(self.fake_context,
                                                 self.subnet_dict['id'])

        self.assertEqual(len(share_servers),
                         len(result['share_servers']))

        for index, share_server in enumerate(share_servers):
            result = db_api.share_network_subnet_get_all_by_share_server_id(
                self.fake_context, share_server['id'])
            for key, value in share_server['share_network_subnets'][0].items():
                if key != 'share_servers':
                    self.assertEqual(value, result[0][key])

    def test_get_not_found(self):
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        self.assertRaises(exception.ShareNetworkSubnetNotFound,
                          db_api.share_network_subnet_get,
                          self.fake_context,
                          'fake_id')

    def test_delete(self):
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_delete(self.fake_context,
                                           self.subnet_dict['id'])

        self.assertRaises(exception.ShareNetworkSubnetNotFound,
                          db_api.share_network_subnet_delete,
                          self.fake_context,
                          self.subnet_dict['id'])

    def test_delete_not_found(self):
        self.assertRaises(exception.ShareNetworkSubnetNotFound,
                          db_api.share_network_subnet_delete,
                          self.fake_context,
                          'fake_id')

    def test_update(self):
        update_dict = {
            'gateway': 'fake_gateway',
            'ip_version': 6,
            'mtu': ''
        }

        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_update(
            self.fake_context, self.subnet_dict['id'], update_dict)

        result = db_api.share_network_subnet_get(self.fake_context,
                                                 self.subnet_dict['id'])
        self._check_fields(expected=update_dict, actual=result)

    def test_update_not_found(self):
        self.assertRaises(exception.ShareNetworkSubnetNotFound,
                          db_api.share_network_subnet_update,
                          self.fake_context,
                          self.subnet_dict['id'],
                          {})

    @ddt.data([
        {
            'id': 'sn_id1',
            'project_id': 'fake project',
            'user_id': 'fake'
        }
    ], [
        {
            'id': 'fake_id',
            'project_id': 'fake project',
            'user_id': 'fake'
        },
        {
            'id': 'sn_id2',
            'project_id': 'fake project',
            'user_id': 'fake'
        }
    ])
    def test_get_all_by_share_network(self, share_networks):

        for idx, share_network in enumerate(share_networks):
            self.subnet_dict['share_network_id'] = share_network['id']
            self.subnet_dict['id'] = 'fake_id%s' % idx

            db_api.share_network_create(self.fake_context, share_network)
            db_api.share_network_subnet_create(self.fake_context,
                                               self.subnet_dict)
        for share_network in share_networks:
            subnets = db_api.share_network_subnet_get_all_by_share_network(
                self.fake_context, share_network['id'])
            self.assertEqual(1, len(subnets))

    def test_get_by_availability_zone_id(self):
        with db_api.context_manager.writer.using(self.fake_context):
            az = db_api._availability_zone_create_if_not_exist(
                self.fake_context, 'fake_zone_id',
            )
        self.subnet_dict['availability_zone_id'] = az['id']
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        result = db_api.share_network_subnets_get_all_by_availability_zone_id(
            self.fake_context, self.subnet_dict['share_network_id'], az['id'])

        self._check_fields(expected=self.subnet_dict, actual=result[0])

    def test_get_az_subnets(self):
        with db_api.context_manager.writer.using(self.fake_context):
            az = db_api._availability_zone_create_if_not_exist(
                self.fake_context, 'fake_zone_id',
            )
        self.subnet_dict['availability_zone_id'] = az['id']
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        result = db_api.share_network_subnet_get_all_with_same_az(
            self.fake_context, self.subnet_dict['id'])

        self.subnet_dict['share_network'] = None

        self._check_fields(expected=self.subnet_dict, actual=result[0])

    def test_get_az_subnets_not_found(self):
        self.assertRaises(
            exception.ShareNetworkSubnetNotFound,
            db_api.share_network_subnet_get_all_with_same_az,
            self.fake_context, 'share_network_subnet_id')

    def test_get_default_subnet(self):
        db_api.share_network_subnet_create(self.fake_context, self.subnet_dict)

        result = db_api.share_network_subnet_get_default_subnets(
            self.fake_context, self.subnet_dict['share_network_id'])

        self._check_fields(expected=self.subnet_dict, actual=result[0])

    def test_get_by_share_server_id_not_found(self):
        self.assertRaises(
            exception.ShareNetworkSubnetNotFoundByShareServer,
            db_api.share_network_subnet_get_all_by_share_server_id,
            self.fake_context, 'share_server_id')

    def test_share_network_subnet_metadata_get(self):
        metadata = {'a': 'b', 'c': 'd'}

        subnet_1 = db_api.share_network_subnet_create(
            self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_metadata_update(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            metadata, db_api.share_network_subnet_metadata_get(
                self.fake_context, share_network_subnet_id=subnet_1['id']))

    def test_share_network_subnet_metadata_get_item(self):
        metadata = {'a': 'b', 'c': 'd'}
        key = 'a'
        shouldbe = {'a': 'b'}
        subnet_1 = db_api.share_network_subnet_create(
            self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_metadata_update(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            metadata=metadata, delete=False)
        self.assertEqual(
            shouldbe, db_api.share_network_subnet_metadata_get_item(
                self.fake_context, share_network_subnet_id=subnet_1['id'],
                key=key))

    def test_share_network_subnet_metadata_update(self):
        metadata1 = {'a': '1', 'c': '2'}
        metadata2 = {'a': '3', 'd': '5'}
        should_be = {'a': '3', 'c': '2', 'd': '5'}
        subnet_1 = db_api.share_network_subnet_create(
            self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_metadata_update(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            metadata=metadata1, delete=False)
        db_api.share_network_subnet_metadata_update(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            metadata=metadata2, delete=False)
        self.assertEqual(
            should_be, db_api.share_network_subnet_metadata_get(
                self.fake_context, share_network_subnet_id=subnet_1['id']))

    def test_share_network_subnet_metadata_delete(self):
        key = 'a'
        metadata = {'a': '1', 'c': '2'}
        should_be = {'c': '2'}
        subnet_1 = db_api.share_network_subnet_create(
            self.fake_context, self.subnet_dict)
        db_api.share_network_subnet_metadata_update(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            metadata=metadata, delete=False)
        db_api.share_network_subnet_metadata_delete(
            self.fake_context, share_network_subnet_id=subnet_1['id'],
            key=key)
        self.assertEqual(
            should_be, db_api.share_network_subnet_metadata_get(
                self.fake_context, share_network_subnet_id=subnet_1['id']))


@ddt.ddt
class SecurityServiceDatabaseAPITestCase(BaseDatabaseAPITestCase):

    def __init__(self, *args, **kwargs):
        super(SecurityServiceDatabaseAPITestCase, self).__init__(*args,
                                                                 **kwargs)

        self.fake_context = context.RequestContext(user_id='fake user',
                                                   project_id='fake project',
                                                   is_admin=False)

    def _check_expected_fields(self, result, expected):
        for key in expected:
            self.assertEqual(expected[key], result[key])

    def test_create(self):
        result = db_api.security_service_create(self.fake_context,
                                                security_service_dict)

        self._check_expected_fields(result, security_service_dict)

    def test_create_with_duplicated_id(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        self.assertRaises(db_exception.DBDuplicateEntry,
                          db_api.security_service_create,
                          self.fake_context,
                          security_service_dict)

    def test_get(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_get(self.fake_context,
                                             security_service_dict['id'])

        self._check_expected_fields(result, security_service_dict)

    def test_get_not_found(self):
        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_get,
                          self.fake_context,
                          'wrong id')

    def test_get_all_by_share_network(self):
        dict1 = security_service_dict
        dict2 = security_service_dict.copy()
        dict2['id'] = 'fake id 2'
        db_api.security_service_create(self.fake_context,
                                       dict1)
        db_api.security_service_create(self.fake_context,
                                       dict2)
        share_nw_dict = {'id': 'fake network id',
                         'project_id': 'fake project',
                         'user_id': 'fake_user_id'}
        db_api.share_network_create(self.fake_context, share_nw_dict)
        db_api.share_network_add_security_service(
            self.fake_context,
            share_nw_dict['id'], dict1['id'])

        result = db_api.security_service_get_all_by_share_network(
            self.fake_context, share_nw_dict['id'])
        self._check_expected_fields(result[0], dict1)
        self.assertEqual(1, len(result))

    def test_delete(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        db_api.security_service_delete(self.fake_context,
                                       security_service_dict['id'])

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_get,
                          self.fake_context,
                          security_service_dict['id'])

    def test_update(self):
        update_dict = {
            'dns_ip': 'new dns',
            'server': 'new ldap server',
            'domain': 'new ldap domain',
            'default_ad_site': 'new ldap default_ad_site',
            'ou': 'new ldap ou',
            'user': 'new user',
            'password': 'new password',
            'name': 'new whatever',
            'description': 'new nevermind',
        }

        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_update(self.fake_context,
                                                security_service_dict['id'],
                                                update_dict)

        self._check_expected_fields(result, update_dict)

    def test_update_no_updates(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_update(self.fake_context,
                                                security_service_dict['id'],
                                                {})

        self._check_expected_fields(result, security_service_dict)

    def test_update_not_found(self):
        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_update,
                          self.fake_context,
                          'wrong id',
                          {})

    def test_get_all_no_records(self):
        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(0, len(result))

    @ddt.data(1, 2)
    def test_get_all(self, records_count):
        index = 0
        services = []
        while index < records_count:
            service_dict = dict(security_service_dict)
            service_dict.update({'id': 'fake_id%s' % index})
            services.append(service_dict)
            db_api.security_service_create(self.fake_context, service_dict)
            index += 1

        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(len(services), len(result))
        for index, service in enumerate(services):
            self._check_fields(expected=service, actual=result[index])

    def test_get_all_two_records(self):
        dict1 = security_service_dict
        dict2 = security_service_dict.copy()
        dict2['id'] = 'fake id 2'
        db_api.security_service_create(self.fake_context,
                                       dict1)
        db_api.security_service_create(self.fake_context,
                                       dict2)

        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(2, len(result))

    def test_get_all_by_project(self):
        dict1 = security_service_dict
        dict2 = security_service_dict.copy()
        dict2['id'] = 'fake id 2'
        dict2['project_id'] = 'fake project 2'
        db_api.security_service_create(self.fake_context,
                                       dict1)
        db_api.security_service_create(self.fake_context,
                                       dict2)

        result1 = db_api.security_service_get_all_by_project(
            self.fake_context,
            dict1['project_id'])

        self.assertEqual(1, len(result1))
        self._check_expected_fields(result1[0], dict1)

        result2 = db_api.security_service_get_all_by_project(
            self.fake_context,
            dict2['project_id'])

        self.assertEqual(1, len(result2))
        self._check_expected_fields(result2[0], dict2)


@ddt.ddt
class ShareServerDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareServerDatabaseAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id',
                                           is_admin=True)
        self.share_net_subnets = [
            db_utils.create_share_network_subnet(
                id=uuidutils.generate_uuid(),
                share_network_id=uuidutils.generate_uuid())]

    def test_share_server_get(self):
        expected = db_utils.create_share_server(
            share_network_subnets=self.share_net_subnets)
        server = db_api.share_server_get(self.ctxt, expected['id'])
        self.assertEqual(expected['id'], server['id'])
        self.assertEqual(expected.share_network_subnets[0]['id'],
                         server.share_network_subnets[0]['id'])
        self.assertEqual(
            expected.share_network_subnets[0]['share_network_id'],
            server.share_network_subnets[0]['share_network_id'])
        self.assertEqual(expected.host, server.host)
        self.assertEqual(expected.status, server.status)

    def test_get_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_get, self.ctxt, fake_id)

    def test_create(self):
        server = db_utils.create_share_server(
            share_network_subnets=self.share_net_subnets)
        self.assertTrue(server['id'])
        self.assertEqual(server.share_network_subnets[0]['id'],
                         server['share_network_subnets'][0]['id'])
        self.assertEqual(
            server.share_network_subnets[0]['share_network_id'],
            server['share_network_subnets'][0]['share_network_id'])
        self.assertEqual(server.host, server['host'])
        self.assertEqual(server.status, server['status'])

    def test_delete(self):
        server = db_utils.create_share_server()
        num_records = len(db_api.share_server_get_all(self.ctxt))
        db_api.share_server_delete(self.ctxt, server['id'])
        self.assertEqual(num_records - 1,
                         len(db_api.share_server_get_all(self.ctxt)))

    def test_delete_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_delete,
                          self.ctxt, fake_id)

    def test_update(self):
        share_net_subnets_update = [
            db_utils.create_share_network_subnet(
                id=uuidutils.generate_uuid(),
                share_network_id=uuidutils.generate_uuid())]
        update = {
            'share_network_subnets': share_net_subnets_update,
            'host': 'update_host',
            'status': constants.STATUS_ACTIVE,
        }
        server = db_utils.create_share_server(
            share_network_subnets=self.share_net_subnets)
        updated_server = db_api.share_server_update(self.ctxt, server['id'],
                                                    update)
        self.assertEqual(server['id'], updated_server['id'])
        self.assertEqual(
            update['share_network_subnets'][0]['share_network_id'],
            updated_server.share_network_subnets[0]['share_network_id'])
        self.assertEqual(update['host'], updated_server.host)
        self.assertEqual(update['status'], updated_server.status)

    def test_update_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_update,
                          self.ctxt, fake_id, {})

    def test_get_all_by_host_and_share_subnet_valid(self):
        subnet_1 = {
            'id': '1',
            'share_network_id': '1',
        }
        subnet_2 = {
            'id': '2',
            'share_network_id': '2',
        }
        share_net_subnets1 = db_utils.create_share_network_subnet(**subnet_1)
        share_net_subnets2 = db_utils.create_share_network_subnet(**subnet_2)
        valid = {
            'share_network_subnets': [share_net_subnets1],
            'host': 'host1',
            'status': constants.STATUS_ACTIVE,
        }
        invalid = {
            'share_network_subnets': [share_net_subnets2],
            'host': 'host1',
            'status': constants.STATUS_ERROR,
        }
        other = {
            'share_network_subnets': [share_net_subnets1],
            'host': 'host2',
            'status': constants.STATUS_ACTIVE,
        }
        valid = db_utils.create_share_server(**valid)
        db_utils.create_share_server(**invalid)
        db_utils.create_share_server(**other)

        servers = db_api.share_server_get_all_by_host_and_share_subnet_valid(
            self.ctxt,
            host='host1',
            share_subnet_id='1')

        self.assertEqual(valid['id'], servers[0]['id'])

    def test_get_all_by_host_and_share_subnet_valid_not_found(self):
        self.assertRaises(
            exception.ShareServerNotFound,
            db_api.share_server_get_all_by_host_and_share_subnet_valid,
            self.ctxt, host='fake', share_subnet_id='fake'
        )

    def test_get_all_by_host_and_share_subnet(self):
        subnet_1 = {
            'id': '1',
            'share_network_id': '1',
        }
        share_net_subnets1 = db_utils.create_share_network_subnet(**subnet_1)
        valid = {
            'share_network_subnets': [share_net_subnets1],
            'host': 'host1',
            'status': constants.STATUS_SERVER_NETWORK_CHANGE,
        }
        other = {
            'share_network_subnets': [share_net_subnets1],
            'host': 'host1',
            'status': constants.STATUS_ERROR,
        }
        invalid = {
            'share_network_subnets': [share_net_subnets1],
            'host': 'host2',
            'status': constants.STATUS_ACTIVE,
        }
        valid = db_utils.create_share_server(**valid)
        invalid = db_utils.create_share_server(**invalid)
        other = db_utils.create_share_server(**other)

        servers = db_api.share_server_get_all_by_host_and_share_subnet(
            self.ctxt,
            host='host1',
            share_subnet_id='1')

        self.assertEqual(2, len(servers))
        ids = [s['id'] for s in servers]
        self.assertTrue(valid['id'] in ids)
        self.assertTrue(other['id'] in ids)
        self.assertFalse(invalid['id'] in ids)

    def test_get_all_by_host_and_share_subnet_not_found(self):
        self.assertRaises(
            exception.ShareServerNotFound,
            db_api.share_server_get_all_by_host_and_share_subnet,
            self.ctxt, host='fake', share_subnet_id='fake'
        )

    def test_get_all(self):
        srv1 = {
            'host': 'host1',
            'status': constants.STATUS_ACTIVE,
        }
        srv2 = {
            'host': 'host1',
            'status': constants.STATUS_ERROR,
        }
        srv3 = {
            'host': 'host2',
            'status': constants.STATUS_ACTIVE,
        }
        servers = db_api.share_server_get_all(self.ctxt)
        self.assertEqual(0, len(servers))

        to_delete = db_utils.create_share_server(**srv1)
        db_utils.create_share_server(**srv2)
        db_utils.create_share_server(**srv3)

        servers = db_api.share_server_get_all(self.ctxt)
        self.assertEqual(3, len(servers))

        db_api.share_server_delete(self.ctxt, to_delete['id'])
        servers = db_api.share_server_get_all(self.ctxt)
        self.assertEqual(2, len(servers))

    def test_backend_details_set(self):
        details = {
            'value1': '1',
            'value2': '2',
        }
        server = db_utils.create_share_server()
        db_api.share_server_backend_details_set(self.ctxt, server['id'],
                                                details)

        self.assertDictEqual(
            details,
            db_api.share_server_get(self.ctxt, server['id'])['backend_details']
        )

        details.update({'value2': '4'})
        db_api.share_server_backend_details_set(self.ctxt, server['id'],
                                                details)
        self.assertDictEqual(
            details,
            db_api.share_server_get(self.ctxt, server['id'])['backend_details']
        )

    def test_backend_details_set_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_backend_details_set,
                          self.ctxt, fake_id, {})

    def test_get_with_details(self):
        values = {
            'share_network_subnets': [
                db_utils.create_share_network_subnet(
                    id='fake_subnet_id',
                    share_network_id='fake_share_net_id')],
            'host': 'hostname',
            'status': constants.STATUS_ACTIVE,
        }
        details = {
            'value1': '1',
            'value2': '2',
        }
        srv_id = db_utils.create_share_server(**values)['id']
        db_api.share_server_backend_details_set(self.ctxt, srv_id, details)
        server = db_api.share_server_get(self.ctxt, srv_id)
        self.assertEqual(srv_id, server['id'])
        self.assertEqual(values['share_network_subnets'][0]['id'],
                         server.share_network_subnets[0]['id'])
        self.assertEqual(
            values['share_network_subnets'][0]['share_network_id'],
            server.share_network_subnets[0]['share_network_id'])
        self.assertEqual(values['host'], server.host)
        self.assertEqual(values['status'], server.status)
        self.assertDictEqual(server['backend_details'], details)
        self.assertIn('backend_details', server.to_dict())

    def test_delete_with_details(self):
        server = db_utils.create_share_server(backend_details={
            'value1': '1',
            'value2': '2',
        })

        num_records = len(db_api.share_server_get_all(self.ctxt))
        db_api.share_server_delete(self.ctxt, server['id'])
        self.assertEqual(num_records - 1,
                         len(db_api.share_server_get_all(self.ctxt)))

    @ddt.data('fake', '-fake-', 'foo_some_fake_identifier_bar',
              'foo-some-fake-identifier-bar', 'foobar')
    def test_share_server_search_by_identifier(self, identifier):

        server = {
            'host': 'hostname',
            'status': constants.STATUS_ACTIVE,
            'is_auto_deletable': True,
            'updated_at': datetime.datetime(2018, 5, 1),
            'identifier': 'some_fake_identifier',
        }

        server = db_utils.create_share_server(**server)
        if identifier == 'foobar':
            self.assertRaises(exception.ShareServerNotFound,
                              db_api.share_server_search_by_identifier,
                              self.ctxt, identifier)
        else:
            result = db_api.share_server_search_by_identifier(
                self.ctxt, identifier)
            self.assertEqual(server['id'], result[0]['id'])

    @ddt.data((True, True, True, 3),
              (True, True, False, 2),
              (True, False, False, 1),
              (False, False, False, 0))
    @ddt.unpack
    def test_share_server_get_all_unused_deletable(self,
                                                   server_1_is_auto_deletable,
                                                   server_2_is_auto_deletable,
                                                   server_3_is_auto_deletable,
                                                   expected_len):
        server1 = {
            'host': 'hostname',
            'status': constants.STATUS_ACTIVE,
            'is_auto_deletable': server_1_is_auto_deletable,
            'updated_at': datetime.datetime(2018, 5, 1)
        }
        server2 = {
            'host': 'hostname',
            'status': constants.STATUS_ACTIVE,
            'is_auto_deletable': server_2_is_auto_deletable,
            'updated_at': datetime.datetime(2018, 5, 1)
        }
        server3 = {
            'host': 'hostname',
            'status': constants.STATUS_ACTIVE,
            'is_auto_deletable': server_3_is_auto_deletable,
            'updated_at': datetime.datetime(2018, 5, 1)
        }
        db_utils.create_share_server(**server1)
        db_utils.create_share_server(**server2)
        db_utils.create_share_server(**server3)
        host = 'hostname'
        updated_before = datetime.datetime(2019, 5, 1)

        unused_deletable = db_api.share_server_get_all_unused_deletable(
            self.ctxt, host, updated_before)
        self.assertEqual(expected_len, len(unused_deletable))

    @ddt.data({'host': 'fakepool@fakehost'},
              {'status': constants.STATUS_SERVER_MIGRATING_TO},
              {'source_share_server_id': 'fake_ss_id'},
              {'share_network_id': uuidutils.generate_uuid()})
    def test_share_server_get_all_with_filters(self, filters):
        server_data = copy.copy(filters)
        share_network_id = server_data.pop('share_network_id', None)
        share_network_subnet = {}
        if share_network_id:
            db_utils.create_share_network(id=share_network_id)
            share_network_subnet = db_utils.create_share_network_subnet(
                id=uuidutils.generate_uuid(),
                share_network_id=share_network_id)
            server_data['share_network_subnets'] = [share_network_subnet]
        db_utils.create_share_server(**server_data)
        db_utils.create_share_server()
        filter_keys = filters.keys()

        results = db_api.share_server_get_all_with_filters(self.ctxt, filters)

        self.assertEqual(1, len(results))
        for result in results:
            for key in filter_keys:
                if key == 'share_network_id':
                    self.assertEqual(share_network_subnet['share_network_id'],
                                     filters[key])
                    self.assertEqual(share_network_subnet['id'],
                                     result['share_network_subnets'][0]['id'])
                else:
                    self.assertEqual(result[key], filters[key])

    @ddt.data('fake@fake', 'host1@backend1')
    def test_share_server_get_all_by_host(self, host):
        db_utils.create_share_server(host='fake@fake')
        db_utils.create_share_server(host='host1@backend1')

        share_servers = db_api.share_server_get_all_by_host(self.ctxt, host)

        self.assertEqual(1, len(share_servers))
        for share_server in share_servers:
            self.assertEqual(host, share_server['host'])

    def test_share_servers_update(self):
        servers = [db_utils.create_share_server()
                   for __ in range(1, 3)]
        server_ids = [server['id'] for server in servers]
        values = {'status': constants.STATUS_NETWORK_CHANGE}

        db_api.share_servers_update(
            self.ctxt, server_ids, values)

        share_servers = [
            db_api.share_server_get(self.ctxt, server_id)
            for server_id in server_ids]

        for ss in share_servers:
            self.assertEqual(constants.STATUS_NETWORK_CHANGE, ss['status'])


class ServiceDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(ServiceDatabaseAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id',
                                           is_admin=True)

        self.service_data = {'host': "fake_host",
                             'binary': "fake_binary",
                             'topic': "fake_topic",
                             'report_count': 0,
                             'availability_zone': "fake_zone"}

    def test_create(self):
        service = db_api.service_create(self.ctxt, self.service_data)
        az = db_api.availability_zone_get(self.ctxt, "fake_zone")

        self.assertEqual(az.id, service.availability_zone_id)
        self.assertSubDictMatch(self.service_data, service.to_dict())

    def test_create__az_exists(self):

        # there's no public AZ create method so we have to define one ourselves
        @db_api.context_manager.writer
        def availability_zone_create(context, name):
            return db_api._availability_zone_create_if_not_exist(
                context, name,
            )

        az = availability_zone_create(self.ctxt, 'fake_zone')
        service = db_api.service_create(self.ctxt, self.service_data)

        self.assertEqual(az.id, service.availability_zone_id)
        self.assertSubDictMatch(self.service_data, service.to_dict())

    def test_update(self):
        az_name = 'fake_zone2'
        update_data = {"availability_zone": az_name}

        service = db_api.service_create(self.ctxt, self.service_data)
        db_api.service_update(self.ctxt, service['id'], update_data)
        service = db_api.service_get(self.ctxt, service['id'])

        az = db_api.availability_zone_get(self.ctxt, az_name)
        self.assertEqual(az.id, service.availability_zone_id)
        valid_values = self.service_data
        valid_values.update(update_data)
        self.assertSubDictMatch(valid_values, service.to_dict())


@ddt.ddt
class AvailabilityZonesDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(AvailabilityZonesDatabaseAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id',
                                           is_admin=True)

    @ddt.data({'fake': 'fake'}, {}, {'fakeavailability_zone': 'fake'},
              {'availability_zone': None}, {'availability_zone': ''})
    def test__ensure_availability_zone_exists_invalid(self, test_values):
        session = db_api.get_session()

        self.assertRaises(ValueError, db_api._ensure_availability_zone_exists,
                          self.ctxt, test_values, session)

    def test_az_get(self):
        az_name = 'test_az'
        with db_api.context_manager.writer.using(self.ctxt):
            az = db_api._availability_zone_create_if_not_exist(
                self.ctxt, az_name
            )

        az_by_id = db_api.availability_zone_get(self.ctxt, az['id'])
        az_by_name = db_api.availability_zone_get(self.ctxt, az_name)

        self.assertEqual(az_name, az_by_id['name'])
        self.assertEqual(az_name, az_by_name['name'])
        self.assertEqual(az['id'], az_by_id['id'])
        self.assertEqual(az['id'], az_by_name['id'])

    def test_az_get_all(self):
        with db_api.context_manager.writer.using(self.ctxt):
            db_api._availability_zone_create_if_not_exist(self.ctxt, 'test1')
            db_api._availability_zone_create_if_not_exist(self.ctxt, 'test2')
            db_api._availability_zone_create_if_not_exist(self.ctxt, 'test3')

        db_api.service_create(self.ctxt, {'availability_zone': 'test2'})

        actual_result = db_api.availability_zone_get_all(self.ctxt)

        self.assertEqual(1, len(actual_result))
        self.assertEqual('test2', actual_result[0]['name'])


@ddt.ddt
class NetworkAllocationsDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(NetworkAllocationsDatabaseAPITestCase, self).setUp()
        self.user_id = 'user_id'
        self.project_id = 'project_id'
        self.share_server_id = 'foo_share_server_id'
        self.share_network_subnet_id = 'foo_share_network_subnet_id'
        self.ctxt = context.RequestContext(
            user_id=self.user_id, project_id=self.project_id, is_admin=True)
        self.user_network_allocations = [
            {'share_server_id': self.share_server_id,
             'ip_address': '1.1.1.1',
             'status': constants.STATUS_ACTIVE,
             'label': None,
             'share_network_subnet_id': self.share_network_subnet_id},
            {'share_server_id': self.share_server_id,
             'ip_address': '2.2.2.2',
             'status': constants.STATUS_ACTIVE,
             'label': 'user',
             'share_network_subnet_id': self.share_network_subnet_id},
        ]
        self.admin_network_allocations = [
            {'share_server_id': self.share_server_id,
             'ip_address': '3.3.3.3',
             'status': constants.STATUS_ACTIVE,
             'label': 'admin',
             'share_network_subnet_id': None},
            {'share_server_id': self.share_server_id,
             'ip_address': '4.4.4.4',
             'status': constants.STATUS_ACTIVE,
             'label': 'admin',
             'share_network_subnet_id': None},
        ]

    def _setup_network_allocations_get_for_share_server(self):
        # Create share network
        share_network_data = {
            'id': 'foo_share_network_id',
            'user_id': self.user_id,
            'project_id': self.project_id,
        }
        db_api.share_network_create(self.ctxt, share_network_data)

        # Create share network subnet
        share_network_subnet_data = {
            'id': self.share_network_subnet_id,
            'share_network_id': self.user_id,
        }
        db_api.share_network_subnet_create(self.ctxt,
                                           share_network_subnet_data)

        # Create share server
        share_server_data = {
            'id': self.share_server_id,
            'host': 'fake_host',
            'status': 'active',
        }
        db_api.share_server_create(self.ctxt, share_server_data)

        # Create user network allocations
        for user_network_allocation in self.user_network_allocations:
            db_api.network_allocation_create(
                self.ctxt, user_network_allocation)

        # Create admin network allocations
        for admin_network_allocation in self.admin_network_allocations:
            db_api.network_allocation_create(
                self.ctxt, admin_network_allocation)

    def test_get_only_user_network_allocations(self):
        self._setup_network_allocations_get_for_share_server()

        result = db_api.network_allocations_get_for_share_server(
            self.ctxt, self.share_server_id, label='user')

        self.assertEqual(
            len(self.user_network_allocations), len(result))
        for na in result:
            self.assertIn(na.label, (None, 'user'))

    def test_get_only_admin_network_allocations(self):
        self._setup_network_allocations_get_for_share_server()

        result = db_api.network_allocations_get_for_share_server(
            self.ctxt, self.share_server_id, label='admin')

        self.assertEqual(
            len(self.admin_network_allocations), len(result))
        for na in result:
            self.assertEqual(na.label, 'admin')

    def test_get_all_network_allocations(self):
        self._setup_network_allocations_get_for_share_server()

        result = db_api.network_allocations_get_for_share_server(
            self.ctxt, self.share_server_id, label=None)

        self.assertEqual(
            len(self.user_network_allocations +
                self.admin_network_allocations),
            len(result)
        )
        for na in result:
            self.assertIn(na.label, ('admin', 'user', None))

    def test_network_allocation_get(self):
        self._setup_network_allocations_get_for_share_server()

        for allocation in self.admin_network_allocations:
            result = db_api.network_allocation_get(self.ctxt, allocation['id'])

            self.assertIsInstance(result, models.NetworkAllocation)
            self.assertEqual(allocation['id'], result.id)

        for allocation in self.user_network_allocations:
            result = db_api.network_allocation_get(self.ctxt, allocation['id'])

            self.assertIsInstance(result, models.NetworkAllocation)
            self.assertEqual(allocation['id'], result.id)

    def test_network_allocation_get_no_result(self):
        self._setup_network_allocations_get_for_share_server()

        self.assertRaises(exception.NotFound,
                          db_api.network_allocation_get,
                          self.ctxt,
                          id='fake')

    def test_network_allocation_get_by_subnet_id(self):
        self._setup_network_allocations_get_for_share_server()

        result = db_api.network_allocations_get_for_share_server(
            self.ctxt, self.share_server_id,
            subnet_id=self.share_network_subnet_id)

        self.assertEqual(2, len(result))

        for network_allocation in result:
            self.assertIsInstance(network_allocation, models.NetworkAllocation)
            self.assertEqual(self.share_network_subnet_id,
                             network_allocation.share_network_subnet_id)

    @ddt.data(True, False)
    def test_network_allocation_get_read_deleted(self, read_deleted):
        self._setup_network_allocations_get_for_share_server()

        deleted_allocation = {
            'share_server_id': self.share_server_id,
            'ip_address': '1.1.1.1',
            'status': constants.STATUS_ACTIVE,
            'label': None,
            'deleted': True,
        }

        new_obj = db_api.network_allocation_create(self.ctxt,
                                                   deleted_allocation)
        if read_deleted:
            result = db_api.network_allocation_get(self.ctxt, new_obj.id,
                                                   read_deleted=read_deleted)
            self.assertIsInstance(result, models.NetworkAllocation)
            self.assertEqual(new_obj.id, result.id)
        else:
            self.assertRaises(exception.NotFound,
                              db_api.network_allocation_get,
                              self.ctxt,
                              id=self.share_server_id)

    def test_network_allocation_update(self):
        self._setup_network_allocations_get_for_share_server()

        for allocation in self.admin_network_allocations:
            old_obj = db_api.network_allocation_get(self.ctxt,
                                                    allocation['id'])
            self.assertEqual('False', old_obj.deleted)
            updated_object = db_api.network_allocation_update(
                self.ctxt, allocation['id'], {'deleted': 'True'})

            self.assertEqual('True', updated_object.deleted)

    @ddt.data(True, False)
    def test_network_allocation_update_read_deleted(self, read_deleted):
        self._setup_network_allocations_get_for_share_server()

        db_api.network_allocation_update(
            self.ctxt,
            self.admin_network_allocations[0]['id'],
            {'deleted': 'True'}
        )

        if read_deleted:
            updated_object = db_api.network_allocation_update(
                self.ctxt, self.admin_network_allocations[0]['id'],
                {'deleted': 'False'}, read_deleted=read_deleted
            )
            self.assertEqual('False', updated_object.deleted)
        else:
            self.assertRaises(exception.NotFound,
                              db_api.network_allocation_update,
                              self.ctxt,
                              id=self.share_server_id,
                              values={'deleted': read_deleted},
                              read_deleted=read_deleted)


class ReservationDatabaseAPITest(test.TestCase):

    def setUp(self):
        super(ReservationDatabaseAPITest, self).setUp()
        self.context = context.get_admin_context()

    def test_reservation_expire(self):
        quota_usage = db_api.quota_usage_create(self.context, 'fake_project',
                                                'fake_user', 'fake_resource',
                                                0, 12, until_refresh=None)
        with db_api.context_manager.writer.using(self.context):
            for time_s in (-1, 1):
                reservation = db_api._reservation_create(
                    self.context, 'fake_uuid',
                    quota_usage, 'fake_project',
                    'fake_user', 'fake_resource', 10,
                    timeutils.utcnow() +
                    datetime.timedelta(days=time_s),
                )

        db_api.reservation_expire(self.context)

        with db_api.context_manager.reader.using(self.context):
            reservations = db_api._quota_reservations_query(
                self.context, ['fake_uuid'],
            ).all()
        quota_usage = db_api.quota_usage_get(self.context, 'fake_project',
                                             'fake_resource')
        self.assertEqual(1, len(reservations))
        self.assertEqual(reservation['id'], reservations[0]['id'])
        self.assertEqual(2, quota_usage['reserved'])


@ddt.ddt
class PurgeDeletedTest(test.TestCase):

    def setUp(self):
        super(PurgeDeletedTest, self).setUp()
        self.context = context.get_admin_context()

    def _days_ago(self, begin, end):
        return timeutils.utcnow() - datetime.timedelta(
            days=random.randint(begin, end))

    def _turn_on_foreign_key(self):
        engine = db_api.get_engine()
        connection = engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
        finally:
            connection.close()

    @ddt.data({"del_days": 0, "num_left": 0},
              {"del_days": 10, "num_left": 2},
              {"del_days": 20, "num_left": 4})
    @ddt.unpack
    def test_purge_records_with_del_days(self, del_days, num_left):
        fake_now = timeutils.utcnow()
        with mock.patch.object(timeutils, 'utcnow',
                               mock.Mock(return_value=fake_now)):
            # create resources soft-deleted in 0~9, 10~19 days ago
            for start, end in ((0, 9), (10, 19)):
                for unused in range(2):
                    # share type
                    db_utils.create_share_type(id=uuidutils.generate_uuid(),
                                               deleted_at=self._days_ago(start,
                                                                         end))
                    # share
                    share = db_utils.create_share_without_instance(
                        metadata={},
                        deleted_at=self._days_ago(start, end))
                    # create share network
                    network = db_utils.create_share_network(
                        id=uuidutils.generate_uuid(),
                        deleted_at=self._days_ago(start, end))
                    # create security service
                    db_utils.create_security_service(
                        id=uuidutils.generate_uuid(),
                        share_network_id=network.id,
                        deleted_at=self._days_ago(start, end))
                    # create share instance
                    s_instance = db_utils.create_share_instance(
                        id=uuidutils.generate_uuid(),
                        share_network_id=network.id,
                        share_id=share.id)
                    # share access
                    db_utils.create_share_access(
                        id=uuidutils.generate_uuid(),
                        share_id=share['id'],
                        deleted_at=self._days_ago(start, end))
                    # create share server
                    db_utils.create_share_server(
                        id=uuidutils.generate_uuid(),
                        deleted_at=self._days_ago(start, end))
                    # create snapshot
                    db_api.share_snapshot_create(
                        self.context, {'share_id': share['id'],
                                       'deleted_at': self._days_ago(start,
                                                                    end)},
                        create_snapshot_instance=False)
                    # update share instance
                    db_api.share_instance_update(
                        self.context,
                        s_instance.id,
                        {'deleted_at': self._days_ago(start, end)})

            db_api.purge_deleted_records(self.context, age_in_days=del_days)

            for model in [models.ShareTypes, models.Share,
                          models.ShareNetwork, models.ShareAccessMapping,
                          models.ShareInstance, models.ShareServer,
                          models.ShareSnapshot, models.SecurityService]:
                rows = db_api.model_query(self.context, model).count()
                self.assertEqual(num_left, rows)

    def test_purge_records_with_illegal_args(self):
        self.assertRaises(TypeError, db_api.purge_deleted_records,
                          self.context)
        self.assertRaises(exception.InvalidParameterValue,
                          db_api.purge_deleted_records,
                          self.context,
                          age_in_days=-1)

    def test_purge_records_with_constraint(self):
        self._turn_on_foreign_key()
        type_id = uuidutils.generate_uuid()
        # create share type1
        db_utils.create_share_type(id=type_id,
                                   deleted_at=self._days_ago(1, 1))
        # create share type2
        db_utils.create_share_type(id=uuidutils.generate_uuid(),
                                   deleted_at=self._days_ago(1, 1))
        # create share
        share = db_utils.create_share(share_type_id=type_id)

        db_api.purge_deleted_records(self.context, age_in_days=0)
        type_row = db_api.model_query(self.context,
                                      models.ShareTypes).count()
        # share type1 should not be deleted
        self.assertEqual(1, type_row)
        db_api.model_query(self.context, models.ShareInstance).delete()
        db_api.share_delete(self.context, share['id'])

        db_api.purge_deleted_records(self.context, age_in_days=0)
        s_row = db_api.model_query(self.context, models.Share).count()
        type_row = db_api.model_query(self.context,
                                      models.ShareTypes).count()
        self.assertEqual(0, s_row + type_row)


@ddt.ddt
class ShareTypeAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareTypeAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(
            user_id='user_id', project_id='project_id', is_admin=True)

    @ddt.data({'used_by_shares': True, 'used_by_group_types': False},
              {'used_by_shares': False, 'used_by_group_types': True},
              {'used_by_shares': True, 'used_by_group_types': True})
    @ddt.unpack
    def test_share_type_destroy_in_use(self, used_by_shares,
                                       used_by_group_types):
        share_type_1 = db_utils.create_share_type(
            name='orange', extra_specs={'somekey': 'someval'},
            is_public=False, override_defaults=True)
        share_type_2 = db_utils.create_share_type(
            name='regalia', override_defaults=True)
        db_api.share_type_access_add(self.ctxt,
                                     share_type_1['id'],
                                     "2018ndaetfigovnsaslcahfavmrpions")
        db_api.share_type_access_add(self.ctxt,
                                     share_type_1['id'],
                                     "2016ndaetfigovnsaslcahfavmrpions")
        if used_by_shares:
            share_1 = db_utils.create_share(share_type_id=share_type_1['id'])
            db_utils.create_share(share_type_id=share_type_2['id'])
        if used_by_group_types:
            group_type_1 = db_utils.create_share_group_type(
                name='crimson', share_types=[share_type_1['id']])
            db_utils.create_share_group_type(
                name='tide', share_types=[share_type_2['id']])
            share_group_1 = db_utils.create_share_group(
                share_group_type_id=group_type_1['id'],
                share_types=[share_type_1['id']])

        self.assertRaises(exception.ShareTypeInUse,
                          db_api.share_type_destroy,
                          self.ctxt, share_type_1['id'])
        self.assertRaises(exception.ShareTypeInUse,
                          db_api.share_type_destroy,
                          self.ctxt, share_type_2['id'])

        # Let's cleanup share_type_1 and verify it is gone
        if used_by_shares:
            db_api.share_instance_delete(self.ctxt, share_1.instance.id)
        if used_by_group_types:
            db_api.share_group_destroy(self.ctxt, share_group_1['id'])
            db_api.share_group_type_destroy(self.ctxt,
                                            group_type_1['id'])

        self.assertIsNone(
            db_api.share_type_destroy(self.ctxt, share_type_1['id']))
        self.assertDictEqual(
            {}, db_api.share_type_extra_specs_get(
                self.ctxt, share_type_1['id']))
        self.assertRaises(exception.ShareTypeNotFound,
                          db_api.share_type_access_get_all,
                          self.ctxt, share_type_1['id'])
        self.assertRaises(exception.ShareTypeNotFound,
                          db_api.share_type_get,
                          self.ctxt, share_type_1['id'])

        # share_type_2 must still be around
        self.assertEqual(
            share_type_2['id'],
            db_api.share_type_get(self.ctxt, share_type_2['id'])['id'])

    @ddt.data({'usages': False, 'reservations': False},
              {'usages': False, 'reservations': True},
              {'usages': True, 'reservations': False})
    @ddt.unpack
    def test_share_type_destroy_quotas_and_reservations(self, usages,
                                                        reservations):
        share_type = db_utils.create_share_type(name='clemsontigers')
        shares_quota = db_api.quota_create(
            self.ctxt, "fake-project-id", 'shares', 10,
            share_type_id=share_type['id'])
        snapshots_quota = db_api.quota_create(
            self.ctxt, "fake-project-id", 'snapshots', 30,
            share_type_id=share_type['id'])

        if reservations:
            resources = {
                'shares': quota.ReservableResource('shares', '_sync_shares'),
                'snapshots': quota.ReservableResource(
                    'snapshots', '_sync_snapshots'),
            }
            project_quotas = {
                'shares': shares_quota.hard_limit,
                'snapshots': snapshots_quota.hard_limit,
            }
            user_quotas = {
                'shares': shares_quota.hard_limit,
                'snapshots': snapshots_quota.hard_limit,
            }
            deltas = {'shares': 1, 'snapshots': 3}
            expire = timeutils.utcnow() + datetime.timedelta(seconds=86400)
            reservation_uuids = db_api.quota_reserve(
                self.ctxt, resources, project_quotas, user_quotas,
                project_quotas, deltas, expire, False, 30,
                project_id='fake-project-id', share_type_id=share_type['id'])

            with db_api.context_manager.reader.using(self.ctxt):
                q_reservations = db_api._quota_reservations_query(
                    self.ctxt, reservation_uuids,
                ).all()
            # There should be 2 "user" reservations and 2 "share-type"
            # quota reservations
            self.assertEqual(4, len(q_reservations))
            q_share_type_reservations = [qr for qr in q_reservations
                                         if qr['share_type_id'] is not None]
            # There should be exactly two "share type" quota reservations
            self.assertEqual(2, len(q_share_type_reservations))
            for q_reservation in q_share_type_reservations:
                self.assertEqual(q_reservation['share_type_id'],
                                 share_type['id'])

        if usages:
            db_api.quota_usage_create(self.ctxt, 'fake-project-id',
                                      'fake-user-id', 'shares', 3, 2, False,
                                      share_type_id=share_type['id'])
            db_api.quota_usage_create(self.ctxt, 'fake-project-id',
                                      'fake-user-id', 'snapshots', 2, 2, False,
                                      share_type_id=share_type['id'])
            q_usages = db_api.quota_usage_get_all_by_project_and_share_type(
                self.ctxt, 'fake-project-id', share_type['id'])
            self.assertEqual(3, q_usages['shares']['in_use'])
            self.assertEqual(2, q_usages['shares']['reserved'])
            self.assertEqual(2, q_usages['snapshots']['in_use'])
            self.assertEqual(2, q_usages['snapshots']['reserved'])

        # Validate that quotas exist
        share_type_quotas = db_api.quota_get_all_by_project_and_share_type(
            self.ctxt, 'fake-project-id', share_type['id'])
        expected_quotas = {
            'project_id': 'fake-project-id',
            'share_type_id': share_type['id'],
            'shares': 10,
            'snapshots': 30,
        }
        self.assertDictEqual(expected_quotas, share_type_quotas)

        db_api.share_type_destroy(self.ctxt, share_type['id'])

        self.assertRaises(exception.ShareTypeNotFound,
                          db_api.share_type_get,
                          self.ctxt, share_type['id'])
        # Quotas must be gone
        share_type_quotas = db_api.quota_get_all_by_project_and_share_type(
            self.ctxt, 'fake-project-id', share_type['id'])
        self.assertEqual({'project_id': 'fake-project-id',
                          'share_type_id': share_type['id']},
                         share_type_quotas)

        # Check usages and reservations
        if usages:
            q_usages = db_api.quota_usage_get_all_by_project_and_share_type(
                self.ctxt, 'fake-project-id', share_type['id'])
            expected_q_usages = {'project_id': 'fake-project-id',
                                 'share_type_id': share_type['id']}
            self.assertDictEqual(expected_q_usages, q_usages)
        if reservations:
            with db_api.context_manager.reader.using(self.ctxt):
                q_reservations = db_api._quota_reservations_query(
                    self.ctxt, reservation_uuids,
                ).all()
            # just "user" quota reservations should be left, since we didn't
            # clean them up.
            self.assertEqual(2, len(q_reservations))
            for q_reservation in q_reservations:
                self.assertIsNone(q_reservation['share_type_id'])

    @ddt.data(
        (None, None, 5),
        ('fake2', None, 2),
        (None, 'fake', 3),
    )
    @ddt.unpack
    def test_share_replica_data_get_for_project(
            self, user_id, share_type_id, expected_result):
        kwargs = {}
        if share_type_id:
            kwargs.update({'id': share_type_id})
        share_type_1 = db_utils.create_share_type(**kwargs)
        share_type_2 = db_utils.create_share_type()

        share_1 = db_utils.create_share(size=1, user_id='fake',
                                        share_type_id=share_type_1['id'])
        share_2 = db_utils.create_share(size=1, user_id='fake2',
                                        share_type_id=share_type_2['id'])
        project_id = share_1['project_id']
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_id=share_1['id'], share_type_id=share_type_1['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            share_id=share_1['id'], share_type_id=share_type_1['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            share_id=share_1['id'], share_type_id=share_type_1['id'])

        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_ACTIVE,
            share_id=share_2['id'], share_type_id=share_type_2['id'])
        db_utils.create_share_replica(
            replica_state=constants.REPLICA_STATE_IN_SYNC,
            share_id=share_2['id'], share_type_id=share_type_2['id'])

        kwargs = {}
        if user_id:
            kwargs.update({'user_id': user_id})
        if share_type_id:
            kwargs.update({'share_type_id': share_type_id})

        with db_api.context_manager.reader.using(self.ctxt):
            total_amt, total_size = db_api._share_replica_data_get_for_project(
                self.ctxt, project_id, **kwargs,
            )
        self.assertEqual(expected_result, total_amt)
        self.assertEqual(expected_result, total_size)

    def test_share_type_get_by_name_or_id_found_by_id(self):
        share_type = db_utils.create_share_type()

        result = db_api.share_type_get_by_name_or_id(
            self.ctxt, share_type['id'])

        self.assertIsNotNone(result)
        self.assertEqual(share_type['id'], result['id'])

    def test_share_type_get_by_name_or_id_found_by_name(self):
        name = uuidutils.generate_uuid()
        db_utils.create_share_type(name=name)

        result = db_api.share_type_get_by_name_or_id(self.ctxt, name)

        self.assertIsNotNone(result)
        self.assertEqual(name, result['name'])
        self.assertNotEqual(name, result['id'])

    def test_share_type_get_by_name_or_id_when_does_not_exist(self):
        fake_id = uuidutils.generate_uuid()

        result = db_api.share_type_get_by_name_or_id(self.ctxt, fake_id)

        self.assertIsNone(result)

    def test_share_type_get_with_none_id(self):
        self.assertRaises(exception.DefaultShareTypeNotConfigured,
                          db_api.share_type_get, self.ctxt, None)

    @ddt.data(
        {'name': 'st_1', 'description': 'des_1', 'is_public': True},
        {'name': 'st_2', 'description': 'des_2', 'is_public': None},
        {'name': 'st_3', 'description': None, 'is_public': False},
        {'name': None, 'description': 'des_4', 'is_public': True},
    )
    @ddt.unpack
    def test_share_type_update(self, name, description, is_public):
        values = {}
        if name:
            values.update({'name': name})
        if description:
            values.update({'description': description})
        if is_public is not None:
            values.update({'is_public': is_public})
        share_type = db_utils.create_share_type(name='st_name')
        db_api.share_type_update(self.ctxt, share_type['id'], values)
        updated_st = db_api.share_type_get_by_name_or_id(self.ctxt,
                                                         share_type['id'])
        if name:
            self.assertEqual(name, updated_st['name'])
        if description:
            self.assertEqual(description, updated_st['description'])
        if is_public is not None:
            self.assertEqual(is_public, updated_st['is_public'])

    def test_share_type_update_not_found(self):
        share_type = db_utils.create_share_type(name='st_update_test')
        db_api.share_type_destroy(self.ctxt, share_type['id'])
        values = {"name": "not_exist"}
        self.assertRaises(exception.ShareTypeNotFound,
                          db_api.share_type_update,
                          self.ctxt, share_type['id'], values)


class MessagesDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(MessagesDatabaseAPITestCase, self).setUp()
        self.user_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.ctxt = context.RequestContext(
            user_id=self.user_id, project_id=self.project_id, is_admin=False)

    def test_message_create(self):
        result = db_utils.create_message(project_id=self.project_id,
                                         action_id='001')

        self.assertIsNotNone(result['id'])

    def test_message_delete(self):
        result = db_utils.create_message(project_id=self.project_id,
                                         action_id='001')

        db_api.message_destroy(self.ctxt, result)

        self.assertRaises(exception.NotFound, db_api.message_get,
                          self.ctxt, result['id'])

    def test_message_get(self):
        message = db_utils.create_message(project_id=self.project_id,
                                          action_id='001')

        result = db_api.message_get(self.ctxt, message['id'])

        self.assertEqual(message['id'], result['id'])
        self.assertEqual(message['action_id'], result['action_id'])
        self.assertEqual(message['detail_id'], result['detail_id'])
        self.assertEqual(message['project_id'], result['project_id'])
        self.assertEqual(message['message_level'], result['message_level'])

    def test_message_get_not_found(self):
        self.assertRaises(exception.MessageNotFound, db_api.message_get,
                          self.ctxt, 'fake_id')

    def test_message_get_different_project(self):
        message = db_utils.create_message(project_id='another-project',
                                          action_id='001')

        self.assertRaises(exception.MessageNotFound, db_api.message_get,
                          self.ctxt, message['id'])

    def test_message_get_all(self):
        db_utils.create_message(project_id=self.project_id, action_id='001')
        db_utils.create_message(project_id=self.project_id, action_id='001')
        db_utils.create_message(project_id='another-project', action_id='001')

        result = db_api.message_get_all(self.ctxt)

        self.assertEqual(2, len(result))

    def test_message_get_all_as_admin(self):
        db_utils.create_message(project_id=self.project_id, action_id='001')
        db_utils.create_message(project_id=self.project_id, action_id='001')
        db_utils.create_message(project_id='another-project', action_id='001')

        result = db_api.message_get_all(self.ctxt.elevated())

        self.assertEqual(3, len(result))

    def test_message_get_all_with_filter(self):
        for i in ['001', '002', '002']:
            db_utils.create_message(project_id=self.project_id, action_id=i)

        result = db_api.message_get_all(self.ctxt,
                                        filters={'action_id': '002'})

        self.assertEqual(2, len(result))

    def test_message_get_all_with_created_since_or_before_filter(self):
        now = timeutils.utcnow()
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                created_at=now - datetime.timedelta(seconds=1))
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                created_at=now + datetime.timedelta(seconds=1))
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                created_at=now + datetime.timedelta(seconds=2))
        result1 = db_api.message_get_all(self.ctxt,
                                         filters={'created_before': now})
        result2 = db_api.message_get_all(self.ctxt,
                                         filters={'created_since': now})
        self.assertEqual(1, len(result1))
        self.assertEqual(2, len(result2))

    def test_message_get_all_with_invalid_sort_key(self):
        self.assertRaises(exception.InvalidInput, db_api.message_get_all,
                          self.ctxt, sort_key='invalid_key')

    def test_message_get_all_sorted_asc(self):
        ids = []
        for i in ['001', '002', '003']:
            msg = db_utils.create_message(project_id=self.project_id,
                                          action_id=i)
            ids.append(msg.id)

        result = db_api.message_get_all(self.ctxt,
                                        sort_key='action_id',
                                        sort_dir='asc')
        result_ids = [r.id for r in result]
        self.assertEqual(result_ids, ids)

    def test_message_get_all_with_limit_and_offset(self):
        for i in ['001', '002']:
            db_utils.create_message(project_id=self.project_id,
                                    action_id=i)

        result = db_api.message_get_all(self.ctxt, limit=1, offset=1)
        self.assertEqual(1, len(result))

    def test_message_get_all_sorted(self):
        ids = []
        for i in ['003', '002', '001']:
            msg = db_utils.create_message(project_id=self.project_id,
                                          action_id=i)
            ids.append(msg.id)

        # Default the sort direction to descending
        result = db_api.message_get_all(self.ctxt, sort_key='action_id')
        result_ids = [r.id for r in result]
        self.assertEqual(result_ids, ids)

    def test_cleanup_expired_messages(self):
        adm_context = self.ctxt.elevated()

        now = timeutils.utcnow()
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                expires_at=now)
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                expires_at=now - datetime.timedelta(days=1))
        db_utils.create_message(project_id=self.project_id,
                                action_id='001',
                                expires_at=now + datetime.timedelta(days=1))

        with mock.patch.object(timeutils, 'utcnow') as mock_time_now:
            mock_time_now.return_value = now
            db_api.cleanup_expired_messages(adm_context)
            messages = db_api.message_get_all(adm_context)
            self.assertEqual(2, len(messages))


class BackendInfoDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(BackendInfoDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def test_create(self):
        host = "fake_host"
        value = "fake_hash_value"

        initial_data = db_api.backend_info_get(self.ctxt, host)
        db_api.backend_info_update(self.ctxt, host, value)
        actual_data = db_api.backend_info_get(self.ctxt, host)

        self.assertIsNone(initial_data)
        self.assertEqual(value, actual_data['info_hash'])
        self.assertEqual(host, actual_data['host'])

    def test_get(self):
        host = "fake_host"
        value = "fake_hash_value"

        db_api.backend_info_update(self.ctxt, host, value, False)
        actual_result = db_api.backend_info_get(self.ctxt, host)

        self.assertEqual(value, actual_result['info_hash'])
        self.assertEqual(host, actual_result['host'])

    def test_delete(self):
        host = "fake_host"
        value = "fake_hash_value"

        db_api.backend_info_update(self.ctxt, host, value)
        initial_data = db_api.backend_info_get(self.ctxt, host)

        db_api.backend_info_update(self.ctxt, host, delete_existing=True)
        actual_data = db_api.backend_info_get(self.ctxt, host)

        self.assertEqual(value, initial_data['info_hash'])
        self.assertEqual(host, initial_data['host'])
        self.assertIsNone(actual_data)

    def test_double_update(self):
        host = "fake_host"
        value_1 = "fake_hash_value_1"
        value_2 = "fake_hash_value_2"

        initial_data = db_api.backend_info_get(self.ctxt, host)
        db_api.backend_info_update(self.ctxt, host, value_1)
        db_api.backend_info_update(self.ctxt, host, value_2)
        actual_data = db_api.backend_info_get(self.ctxt, host)

        self.assertIsNone(initial_data)
        self.assertEqual(value_2, actual_data['info_hash'])
        self.assertEqual(host, actual_data['host'])


@ddt.ddt
class ShareResourcesAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareResourcesAPITestCase, self).setUp()
        self.context = context.get_admin_context()

    @ddt.data('controller-100', 'controller-0@otherstore03',
              'controller-0@otherstore01#pool200')
    def test_share_resources_host_update_no_matches(self, current_host):
        share_id = uuidutils.generate_uuid()
        share_network_id = uuidutils.generate_uuid()
        share_network_subnet_id = uuidutils.generate_uuid()
        share_net_subnets = [db_utils.create_share_network_subnet(
            id=share_network_subnet_id,
            share_network_id=share_network_id)]
        if '@' in current_host:
            if '#' in current_host:
                new_host = 'new-controller-X@backendX#poolX'
            else:
                new_host = 'new-controller-X@backendX'
        else:
            new_host = 'new-controller-X'
        resources = [  # noqa
            # share
            db_utils.create_share_without_instance(
                id=share_id,
                status=constants.STATUS_AVAILABLE),
            # share instances
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-0@fancystore01#pool100',
                status=constants.STATUS_AVAILABLE),
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-0@otherstore02#pool100',
                status=constants.STATUS_ERROR),
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-2@beststore07#pool200',
                status=constants.STATUS_DELETING),
            # share groups
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-0@fancystore01#pool200',
                status=constants.STATUS_AVAILABLE),
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-0@otherstore02#pool100',
                status=constants.STATUS_ERROR),
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-2@beststore07#pool100',
                status=constants.STATUS_DELETING),
            # share servers
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-0@fancystore01',
                status=constants.STATUS_ACTIVE),
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-0@otherstore02#pool100',
                status=constants.STATUS_ERROR),
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-2@beststore07',
                status=constants.STATUS_DELETING),

        ]

        updates = db_api.share_resources_host_update(self.context,
                                                     current_host,
                                                     new_host)

        expected_updates = {'instances': 0, 'servers': 0, 'groups': 0}
        self.assertDictEqual(expected_updates, updates)
        # validate that resources are unmodified:
        share_instances = db_api.share_instances_get_all(
            self.context, filters={'share_id': share_id})
        share_groups = db_api.share_group_get_all(
            self.context, filters={'share_network_id': share_network_id})
        share_servers = db_api._share_server_get_query(self.context).filter(
            models.ShareServer.share_network_subnets.any(
                id=share_net_subnets[0]['id'])).all()
        self.assertEqual(3, len(share_instances))
        self.assertEqual(3, len(share_groups))
        self.assertEqual(3, len(share_servers))
        for share_instance in share_instances:
            self.assertTrue(not share_instance['host'].startswith(new_host))
        for share_group in share_groups:
            self.assertTrue(not share_group['host'].startswith(new_host))
        for share_server in share_servers:
            self.assertTrue(not share_server['host'].startswith(new_host))

    @ddt.data(
        {'current_host': 'controller-2',
         'expected_updates': {'instances': 1, 'servers': 2, 'groups': 1}},
        {'current_host': 'controller-0@fancystore01',
         'expected_updates': {'instances': 2, 'servers': 1, 'groups': 2}},
        {'current_host': 'controller-0@fancystore01#pool100',
         'expected_updates': {'instances': 1, 'servers': 1, 'groups': 0}})
    @ddt.unpack
    def test_share_resources_host_update_partial_matches(self, current_host,
                                                         expected_updates):
        share_id = uuidutils.generate_uuid()
        share_network_id = uuidutils.generate_uuid()
        share_network_subnet_id = uuidutils.generate_uuid()
        share_net_subnets = [db_utils.create_share_network_subnet(
            id=share_network_subnet_id,
            share_network_id=share_network_id)]
        if '@' in current_host:
            if '#' in current_host:
                new_host = 'new-controller-X@backendX#poolX'
            else:
                new_host = 'new-controller-X@backendX'
        else:
            new_host = 'new-controller-X'
        total_updates_expected = (expected_updates['instances']
                                  + expected_updates['groups']
                                  + expected_updates['servers'])
        resources = [  # noqa
            # share
            db_utils.create_share_without_instance(
                id=share_id,
                status=constants.STATUS_AVAILABLE),
            # share instances
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-0@fancystore01#pool100',
                status=constants.STATUS_AVAILABLE),
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-0@fancystore01#pool200',
                status=constants.STATUS_ERROR),
            db_utils.create_share_instance(
                share_id=share_id,
                host='controller-2@beststore07#pool200',
                status=constants.STATUS_DELETING),
            # share groups
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-0@fancystore01#pool101',
                status=constants.STATUS_ACTIVE),
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-0@fancystore01#pool101',
                status=constants.STATUS_ERROR),
            db_utils.create_share_group(
                share_network_id=share_network_id,
                host='controller-2@beststore07#pool200',
                status=constants.STATUS_DELETING),
            # share servers
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-0@fancystore01#pool100',
                status=constants.STATUS_ACTIVE),
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-2@fancystore01',
                status=constants.STATUS_ERROR),
            db_utils.create_share_server(
                share_network_subnets=share_net_subnets,
                host='controller-2@beststore07#pool200',
                status=constants.STATUS_DELETING),
        ]

        actual_updates = db_api.share_resources_host_update(
            self.context, current_host, new_host)

        share_instances = db_api.share_instances_get_all(
            self.context, filters={'share_id': share_id})
        share_groups = db_api.share_group_get_all(
            self.context, filters={'share_network_id': share_network_id})
        share_servers = db_api._share_server_get_query(self.context).filter(
            models.ShareServer.share_network_subnets.any(
                id=share_net_subnets[0]['id'])).all()

        updated_resources = [
            res for res in share_instances + share_groups + share_servers
            if res['host'].startswith(new_host)
        ]
        self.assertEqual(expected_updates, actual_updates)
        self.assertEqual(total_updates_expected, len(updated_resources))

    def test_share_instances_status_update(self):
        for i in range(1, 3):
            instances = [
                db_utils.create_share_instance(
                    status=constants.STATUS_SERVER_MIGRATING, share_id='fake')
                for __ in range(1, 3)]
        share_instance_ids = [instance['id'] for instance in instances]
        values = {'status': constants.STATUS_AVAILABLE}

        db_api.share_instances_status_update(
            self.context, share_instance_ids, values)

        instances = [
            db_api.share_instance_get(self.context, instance_id)
            for instance_id in share_instance_ids]

        for instance in instances:
            self.assertEqual(constants.STATUS_AVAILABLE, instance['status'])

    def test_share_snapshot_instances_status_update(self):
        share_instance = db_utils.create_share_instance(
            status=constants.STATUS_AVAILABLE, share_id='fake')
        instances = [
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_1', status=constants.STATUS_CREATING,
                share_instance_id=share_instance['id'])
            for __ in range(1, 3)]

        snapshot_instance_ids = [instance['id'] for instance in instances]
        values = {'status': constants.STATUS_AVAILABLE}

        db_api.share_snapshot_instances_status_update(
            self.context, snapshot_instance_ids, values)

        instances = [
            db_api.share_snapshot_instance_get(self.context, instance_id)
            for instance_id in snapshot_instance_ids]

        for instance in instances:
            self.assertEqual(constants.STATUS_AVAILABLE, instance['status'])

    def test_share_and_snapshot_instances_status_update(self):
        share_instance = db_utils.create_share_instance(
            status=constants.STATUS_AVAILABLE, share_id='fake')
        share_instance_ids = [share_instance['id']]
        fake_session = db_api.get_session()
        snap_instances = [
            db_utils.create_snapshot_instance(
                'fake_snapshot_id_1', status=constants.STATUS_CREATING,
                share_instance_id=share_instance['id'])
            for __ in range(1, 3)]

        snapshot_instance_ids = [instance['id'] for instance in snap_instances]
        values = {'status': constants.STATUS_AVAILABLE}

        mock_update_share_instances = self.mock_object(
            db_api, 'share_instances_status_update',
            mock.Mock(return_value=[share_instance]))
        mock_update_snap_instances = self.mock_object(
            db_api, 'share_snapshot_instances_status_update',
            mock.Mock(return_value=snap_instances))
        mock_get_session = self.mock_object(
            db_api, 'get_session', mock.Mock(return_value=fake_session))

        updated_share_instances, updated_snap_instances = (
            db_api.share_and_snapshot_instances_status_update(
                self.context, values, share_instance_ids=share_instance_ids,
                snapshot_instance_ids=snapshot_instance_ids))

        mock_get_session.assert_called()
        mock_update_share_instances.assert_called_once_with(
            self.context, share_instance_ids, values, session=fake_session)
        mock_update_snap_instances.assert_called_once_with(
            self.context, snapshot_instance_ids, values, session=fake_session)
        self.assertEqual(updated_share_instances, [share_instance])
        self.assertEqual(updated_snap_instances, snap_instances)

    @ddt.data(
        {
            'share_instance_status': constants.STATUS_ERROR,
            'snap_instance_status': constants.STATUS_AVAILABLE,
            'expected_exc': exception.InvalidShareInstance
        },
        {
            'share_instance_status': constants.STATUS_AVAILABLE,
            'snap_instance_status': constants.STATUS_ERROR,
            'expected_exc': exception.InvalidShareSnapshotInstance
        }
    )
    @ddt.unpack
    def test_share_and_snapshot_instances_status_update_invalid_status(
            self, share_instance_status, snap_instance_status, expected_exc):
        share_instance = db_utils.create_share_instance(
            status=share_instance_status, share_id='fake')
        share_snapshot_instance = db_utils.create_snapshot_instance(
            'fake_snapshot_id_1', status=snap_instance_status,
            share_instance_id=share_instance['id'])
        share_instance_ids = [share_instance['id']]
        snap_instance_ids = [share_snapshot_instance['id']]
        values = {'status': constants.STATUS_AVAILABLE}
        fake_session = db_api.get_session()

        mock_get_session = self.mock_object(
            db_api, 'get_session', mock.Mock(return_value=fake_session))
        mock_instances_get_all = self.mock_object(
            db_api, 'share_instances_get_all',
            mock.Mock(return_value=[share_instance]))
        mock_snap_instances_get_all = self.mock_object(
            db_api, 'share_snapshot_instance_get_all_with_filters',
            mock.Mock(return_value=[share_snapshot_instance]))

        self.assertRaises(expected_exc,
                          db_api.share_and_snapshot_instances_status_update,
                          self.context,
                          values,
                          share_instance_ids=share_instance_ids,
                          snapshot_instance_ids=snap_instance_ids,
                          current_expected_status=constants.STATUS_AVAILABLE)

        mock_get_session.assert_called()
        mock_instances_get_all.assert_called_once_with(
            self.context, filters={'instance_ids': share_instance_ids},
            session=fake_session)
        if snap_instance_status == constants.STATUS_ERROR:
            mock_snap_instances_get_all.assert_called_once_with(
                self.context, {'instance_ids': snap_instance_ids},
                session=fake_session)


@ddt.ddt
class AsyncOperationDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(AsyncOperationDatabaseAPITestCase, self).setUp()
        self.user_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.ctxt = context.RequestContext(
            user_id=self.user_id, project_id=self.project_id, is_admin=False)

    def _get_async_operation_test_data(self):
        return uuidutils.generate_uuid()

    @ddt.data({"details": {"foo": "bar", "tee": "too"},
               "valid": {"foo": "bar", "tee": "too"}},
              {"details": {"foo": "bar", "tee": ["test"]},
               "valid": {"foo": "bar", "tee": str(["test"])}})
    @ddt.unpack
    def test_update(self, details, valid):
        entity_id = self._get_async_operation_test_data()

        initial_data = db_api.async_operation_data_get(self.ctxt, entity_id)
        db_api.async_operation_data_update(self.ctxt, entity_id, details)
        actual_data = db_api.async_operation_data_get(self.ctxt, entity_id)

        self.assertEqual({}, initial_data)
        self.assertEqual(valid, actual_data)

    @ddt.data({'with_deleted': True, 'append': False},
              {'with_deleted': True, 'append': True},
              {'with_deleted': False, 'append': False},
              {'with_deleted': False, 'append': True})
    @ddt.unpack
    def test_update_with_more_values(self, with_deleted, append):
        entity_id = self._get_async_operation_test_data()
        details = {"tee": "too"}
        more_details = {"foo": "bar"}
        result = {"tee": "too", "foo": "bar"}

        db_api.async_operation_data_update(self.ctxt, entity_id, details)
        if with_deleted:
            db_api.async_operation_data_delete(self.ctxt, entity_id)
        if append:
            more_details.update(details)
        if with_deleted and not append:
            result.pop("tee")
        db_api.async_operation_data_update(self.ctxt, entity_id, more_details)

        actual_result = db_api.async_operation_data_get(self.ctxt, entity_id)

        self.assertEqual(result, actual_result)

    @ddt.data(True, False)
    def test_update_with_duplicate(self, with_deleted):
        entity_id = self._get_async_operation_test_data()
        details = {"tee": "too"}

        db_api.async_operation_data_update(self.ctxt, entity_id, details)
        if with_deleted:
            db_api.async_operation_data_delete(self.ctxt, entity_id)
        db_api.async_operation_data_update(self.ctxt, entity_id, details)

        actual_result = db_api.async_operation_data_get(self.ctxt,
                                                        entity_id)

        self.assertEqual(details, actual_result)

    def test_update_with_delete_existing(self):
        resource_id = self._get_async_operation_test_data()
        details = {"key1": "val1", "key2": "val2", "key3": "val3"}
        details_update = {"key1": "val1_upd", "key4": "new_val"}

        # Create new details
        db_api.async_operation_data_update(self.ctxt, resource_id, details)
        db_api.async_operation_data_update(self.ctxt, resource_id,
                                           details_update,
                                           delete_existing=True)

        actual_result = db_api.async_operation_data_get(self.ctxt, resource_id)

        self.assertEqual(details_update, actual_result)

    def test_get(self):
        resource_id = self._get_async_operation_test_data()
        test_key = "foo"
        test_keys = [test_key, "tee"]
        details = {test_keys[0]: "val", test_keys[1]: "val", "mee": "foo"}
        db_api.async_operation_data_update(self.ctxt, resource_id, details)

        actual_result_all = db_api.async_operation_data_get(
            self.ctxt, resource_id)
        actual_result_single_key = db_api.async_operation_data_get(
            self.ctxt, resource_id, test_key)
        actual_result_list = db_api.async_operation_data_get(
            self.ctxt, resource_id, test_keys)

        self.assertEqual(details, actual_result_all)
        self.assertEqual(details[test_key], actual_result_single_key)
        self.assertEqual(dict.fromkeys(test_keys, "val"), actual_result_list)

    def test_delete_single(self):
        test_id = self._get_async_operation_test_data()
        test_key = "foo"
        details = {test_key: "bar", "tee": "too"}
        valid_result = {"tee": "too"}
        db_api.async_operation_data_update(self.ctxt, test_id, details)

        db_api.async_operation_data_delete(self.ctxt, test_id, test_key)

        actual_result = db_api.async_operation_data_get(
            self.ctxt, test_id)

        self.assertEqual(valid_result, actual_result)

    def test_delete_all(self):
        test_id = self._get_async_operation_test_data()
        details = {"foo": "bar", "tee": "too"}
        db_api.async_operation_data_update(self.ctxt, test_id, details)

        db_api.async_operation_data_delete(self.ctxt, test_id)

        actual_result = db_api.async_operation_data_get(
            self.ctxt, test_id)

        self.assertEqual({}, actual_result)


class TransfersTestCase(test.TestCase):
    """Test case for transfers."""

    def setUp(self):
        super(TransfersTestCase, self).setUp()
        self.user_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.ctxt = context.RequestContext(user_id=self.user_id,
                                           project_id=self.project_id)

    @staticmethod
    def _create_transfer(resource_type='share',
                         resource_id=None, source_project_id=None):
        """Create a transfer object."""
        if resource_id and source_project_id:
            transfer = db_utils.create_transfer(
                resource_type=resource_type,
                resource_id=resource_id,
                source_project_id=source_project_id)
        elif resource_id:
            transfer = db_utils.create_transfer(
                resource_type=resource_type,
                resource_id=resource_id)
        elif source_project_id:
            transfer = db_utils.create_transfer(
                resource_type=resource_type,
                source_project_id=source_project_id)
        else:
            transfer = db_utils.create_transfer(
                resource_type=resource_type)
        return transfer['id']

    def test_transfer_create(self):
        # If the resource_id is Null a KeyError exception will be raised.
        self.assertRaises(KeyError, self._create_transfer)

        share = db_utils.create_share(size=1, user_id=self.user_id,
                                      project_id=self.project_id)
        share_id = share['id']
        self._create_transfer(resource_id=share_id)

    def test_share_transfer_get(self):
        share_id = db_utils.create_share(size=1, user_id=self.user_id,
                                         project_id=self.project_id)['id']
        transfer_id = self._create_transfer(resource_id=share_id)

        transfer = db_api.share_transfer_get(self.ctxt, transfer_id)
        self.assertEqual(share_id, transfer['resource_id'])

        new_ctxt = context.RequestContext(user_id='new_user_id',
                                          project_id='new_project_id')
        self.assertRaises(exception.TransferNotFound,
                          db_api.share_transfer_get, new_ctxt, transfer_id)

        transfer = db_api.share_transfer_get(new_ctxt.elevated(), transfer_id)
        self.assertEqual(share_id, transfer['resource_id'])

    def test_transfer_get_all(self):
        share_id1 = db_utils.create_share(size=1, user_id=self.user_id,
                                          project_id=self.project_id)['id']
        share_id2 = db_utils.create_share(size=1, user_id=self.user_id,
                                          project_id=self.project_id)['id']
        self._create_transfer(resource_id=share_id1,
                              source_project_id=self.project_id)
        self._create_transfer(resource_id=share_id2,
                              source_project_id=self.project_id)

        self.assertRaises(exception.NotAuthorized,
                          db_api.transfer_get_all,
                          self.ctxt)
        transfers = db_api.transfer_get_all(context.get_admin_context())
        self.assertEqual(2, len(transfers))

        transfers = db_api.transfer_get_all_by_project(self.ctxt,
                                                       self.project_id)
        self.assertEqual(2, len(transfers))

        new_ctxt = context.RequestContext(user_id='new_user_id',
                                          project_id='new_project_id')
        transfers = db_api.transfer_get_all_by_project(new_ctxt,
                                                       'new_project_id')
        self.assertEqual(0, len(transfers))

    def test_transfer_destroy(self):
        share_id1 = db_utils.create_share(size=1, user_id=self.user_id,
                                          project_id=self.project_id)['id']
        share_id2 = db_utils.create_share(size=1, user_id=self.user_id,
                                          project_id=self.project_id)['id']
        transfer_id1 = self._create_transfer(resource_id=share_id1,
                                             source_project_id=self.project_id)
        transfer_id2 = self._create_transfer(resource_id=share_id2,
                                             source_project_id=self.project_id)

        transfers = db_api.transfer_get_all(context.get_admin_context())
        self.assertEqual(2, len(transfers))

        db_api.transfer_destroy(self.ctxt, transfer_id1)
        transfers = db_api.transfer_get_all(context.get_admin_context())
        self.assertEqual(1, len(transfers))

        db_api.transfer_destroy(self.ctxt, transfer_id2)
        transfers = db_api.transfer_get_all(context.get_admin_context())
        self.assertEqual(0, len(transfers))

    def test_transfer_accept_then_rollback(self):
        share = db_utils.create_share(size=1, user_id=self.user_id,
                                      project_id=self.project_id)
        transfer_id = self._create_transfer(resource_id=share['id'],
                                            source_project_id=self.project_id)
        new_ctxt = context.RequestContext(user_id='new_user_id',
                                          project_id='new_project_id')

        transfer = db_api.share_transfer_get(new_ctxt.elevated(), transfer_id)
        self.assertEqual(share['project_id'], transfer['source_project_id'])
        self.assertFalse(transfer['accepted'])
        self.assertIsNone(transfer['destination_project_id'])
        # accept the transfer
        db_api.transfer_accept(new_ctxt.elevated(), transfer_id,
                               'new_user_id', 'new_project_id')

        transfer = db_api.model_query(
            new_ctxt.elevated(), models.Transfer,
            read_deleted='yes').filter_by(id=transfer_id).first()
        share = db_api.share_get(new_ctxt.elevated(), share['id'])

        self.assertEqual(share['project_id'], 'new_project_id')
        self.assertEqual(share['user_id'], 'new_user_id')
        self.assertTrue(transfer['accepted'])
        self.assertEqual('new_project_id', transfer['destination_project_id'])

        # then test rollback the transfer
        db_api.transfer_accept_rollback(new_ctxt.elevated(), transfer_id,
                                        self.user_id, self.project_id)
        transfer = db_api.model_query(
            new_ctxt.elevated(),
            models.Transfer).filter_by(id=transfer_id).first()
        share = db_api.share_get(new_ctxt.elevated(), share['id'])

        self.assertEqual(share['project_id'], self.project_id)
        self.assertEqual(share['user_id'], self.user_id)
        self.assertFalse(transfer['accepted'])


class ShareBackupDatabaseAPITestCase(BaseDatabaseAPITestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareBackupDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()
        self.backup = {
            'id': 'fake_backup_id',
            'host': "fake_host",
            'user_id': 'fake',
            'project_id': 'fake',
            'availability_zone': 'fake_availability_zone',
            'status': constants.STATUS_CREATING,
            'progress': '0',
            'display_name': 'fake_name',
            'display_description': 'fake_description',
            'size': 1,
        }
        self.share_id = "fake_share_id"

    def test_create_share_backup(self):
        result = db_api.share_backup_create(
            self.ctxt, self.share_id, self.backup)
        self._check_fields(expected=self.backup, actual=result)

    def test_get(self):
        db_api.share_backup_create(
            self.ctxt, self.share_id, self.backup)
        result = db_api.share_backup_get(
            self.ctxt, self.backup['id'])
        self._check_fields(expected=self.backup, actual=result)

    def test_delete(self):
        db_api.share_backup_create(
            self.ctxt, self.share_id, self.backup)
        db_api.share_backup_delete(self.ctxt,
                                   self.backup['id'])

        self.assertRaises(exception.ShareBackupNotFound,
                          db_api.share_backup_get,
                          self.ctxt,
                          self.backup['id'])

    def test_delete_not_found(self):
        self.assertRaises(exception.ShareBackupNotFound,
                          db_api.share_backup_delete,
                          self.ctxt,
                          'fake not exist id')

    def test_update(self):
        new_status = constants.STATUS_ERROR
        db_api.share_backup_create(
            self.ctxt, self.share_id, self.backup)
        result_update = db_api.share_backup_update(
            self.ctxt, self.backup['id'],
            {'status': constants.STATUS_ERROR})
        result_get = db_api.share_backup_get(self.ctxt,
                                             self.backup['id'])
        self.assertEqual(new_status, result_update['status'])
        self._check_fields(expected=dict(result_update.items()),
                           actual=dict(result_get.items()))

    def test_update_not_found(self):
        self.assertRaises(exception.ShareBackupNotFound,
                          db_api.share_backup_update,
                          self.ctxt,
                          'fake id',
                          {})


class ResourceLocksTestCase(test.TestCase):
    """Test case for resource locks."""

    def setUp(self):
        super(ResourceLocksTestCase, self).setUp()
        self.user_id = uuidutils.generate_uuid(dashed=False)
        self.project_id = uuidutils.generate_uuid(dashed=False)
        self.ctxt = context.RequestContext(user_id=self.user_id,
                                           project_id=self.project_id)

    def test_resource_lock_create(self):
        lock_data = {
            'resource_id': uuidutils.generate_uuid(),
            'resource_type': 'share',
            'resource_action': 'delete',
            'lock_context': 'user',
            'user_id': self.user_id,
            'project_id': self.project_id,
            'lock_reason': 'xyzzyspoon!',
        }
        lock = db_api.resource_lock_create(self.ctxt, lock_data)

        self.assertTrue(uuidutils.is_uuid_like(lock['id']))
        self.assertEqual(lock_data['user_id'], lock['user_id'])
        self.assertEqual(lock_data['project_id'], lock['project_id'])
        self.assertIsNone(lock['updated_at'])
        self.assertEqual('False', lock['deleted'])

    def test_resource_lock_update_invalid(self):
        self.assertRaises(exception.ResourceLockNotFound,
                          db_api.resource_lock_update,
                          self.ctxt,
                          'invalid-lock-id',
                          {'lock_reason': 'yadayada'})

    def test_resource_lock_update(self):
        lock = db_utils.create_lock(project_id=self.project_id)
        updated_lock = db_api.resource_lock_update(
            self.ctxt,
            lock['id'],
            {'lock_reason': 'new reason'},
        )

        self.assertEqual(lock['id'], updated_lock['id'])
        self.assertEqual('new reason', updated_lock['lock_reason'])
        self.assertEqual(lock['user_id'], updated_lock['user_id'])
        self.assertEqual(lock['project_id'], updated_lock['project_id'])

        lock_get = db_api.resource_lock_get(self.ctxt, lock['id'])

        self.assertEqual(lock['id'], lock_get['id'])
        self.assertEqual('new reason', lock_get['lock_reason'])
        self.assertEqual(lock['user_id'], lock_get['user_id'])
        self.assertEqual(lock['project_id'], lock_get['project_id'])

    def test_resource_lock_delete_invalid(self):
        self.assertRaises(exception.ResourceLockNotFound,
                          db_api.resource_lock_delete,
                          self.ctxt,
                          'invalid-lock-id')

    def test_resource_lock_delete(self):
        lock = db_utils.create_lock(project_id=self.project_id)
        lock_get = db_api.resource_lock_get(self.ctxt, lock['id'])

        return_value = db_api.resource_lock_delete(self.ctxt, lock['id'])

        self.assertIsNone(return_value)
        self.assertRaises(exception.ResourceLockNotFound,
                          db_api._resource_lock_get,
                          self.ctxt,
                          lock_get['id'])

    def test_resource_lock_get_invalid(self):
        self.assertRaises(exception.ResourceLockNotFound,
                          db_api.resource_lock_get,
                          self.ctxt,
                          'invalid-lock-id')

    def test_resource_lock_get(self):
        lock = db_utils.create_lock(project_id=self.project_id)

        lock_get = db_api.resource_lock_get(self.ctxt, lock['id'])

        self.assertEqual(lock['id'], lock_get['id'])
        self.assertEqual('for the tests', lock_get['lock_reason'])
        self.assertEqual(lock['user_id'], lock_get['user_id'])
        self.assertEqual(lock['project_id'], lock_get['project_id'])

    def test_resource_lock_get_all_basic_filters(self):
        user_id_2 = uuidutils.generate_uuid(dashed=False)
        project_id_2 = uuidutils.generate_uuid(dashed=False)

        lk_1 = db_utils.create_lock(lock_reason='austin',
                                    user_id=self.user_id,
                                    project_id=self.project_id)
        lk_2 = db_utils.create_lock(lock_reason='bexar',
                                    user_id=self.user_id,
                                    project_id=self.project_id)
        lk_3 = db_utils.create_lock(lock_reason='cactus',
                                    user_id=self.user_id,
                                    project_id=self.project_id)
        lk_4 = db_utils.create_lock(lock_reason='diablo',
                                    user_id=user_id_2,
                                    project_id=project_id_2)
        lk_5 = db_utils.create_lock(lock_reason='essex')

        project_locks_limited_offset, count = db_api.resource_lock_get_all(
            self.ctxt, limit=2, offset=1, show_count=True)
        self.assertEqual(2, len(project_locks_limited_offset))
        self.assertEqual(3, count)
        order_expected = [lk_2['id'], lk_1['id']]
        self.assertEqual(order_expected,
                         [lock['id'] for lock in project_locks_limited_offset])

        all_project_locks, count = db_api.resource_lock_get_all(
            self.ctxt, filters={'all_projects': True}, sort_dir='asc')
        self.assertEqual(5, len(all_project_locks))
        order_expected = [
            lk_1['id'], lk_2['id'], lk_3['id'], lk_4['id'], lk_5['id']
        ]
        self.assertEqual(order_expected,
                         [lock['id'] for lock in all_project_locks])
        self.assertTrue(lk_5['project_id']
                        not in [self.project_id, project_id_2])
        self.assertIsNone(count)

        filtered_locks, count = db_api.resource_lock_get_all(
            self.ctxt, filters={'lock_reason~': 'xar'})
        self.assertEqual(1, len(filtered_locks))
        self.assertIsNone(count)
        self.assertEqual(lk_2['id'], filtered_locks[0]['id'])

    def test_resource_locks_get_all_time_filters(self):
        now = timeutils.utcnow()
        lock_1 = db_utils.create_lock(
            lock_reason='folsom',
            project_id=self.project_id,
            created_at=now - datetime.timedelta(seconds=1),
        )
        lock_2 = db_utils.create_lock(
            lock_reason='grizly',
            project_id=self.project_id,
            created_at=now + datetime.timedelta(seconds=1),
        )
        lock_3 = db_utils.create_lock(
            lock_reason='havana',
            project_id=self.project_id,
            created_at=now + datetime.timedelta(seconds=2),
        )

        filters1 = {'created_before': now}
        filters2 = {'created_since': now}

        result1, count1 = db_api.resource_lock_get_all(
            self.ctxt, filters=filters1)
        result2, count2 = db_api.resource_lock_get_all(
            self.ctxt, filters=filters2)

        self.assertEqual(1, len(result1))
        self.assertEqual(lock_1['id'], result1[0]['id'])
        self.assertEqual(2, len(result2))
        self.assertEqual([lock_3['id'], lock_2['id']],
                         [lock['id'] for lock in result2])
        self.assertIsNone(count1)
        self.assertIsNone(count2)

        filters1.update(filters2)
        result3, count3 = db_api.resource_lock_get_all(
            self.ctxt, filters=filters1, show_count=True)
        self.assertEqual(0, len(result3))
        self.assertEqual(0, count3)
