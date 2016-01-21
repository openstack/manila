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

import ddt
from oslo_db import exception as db_exception
from oslo_utils import uuidutils
import six

from manila.common import constants
from manila import context
from manila.db.sqlalchemy import api as db_api
from manila.db.sqlalchemy import models
from manila import exception
from manila import test
from manila.tests import db_utils

security_service_dict = {
    'id': 'fake id',
    'project_id': 'fake project',
    'type': 'ldap',
    'dns_ip': 'fake dns',
    'server': 'fake ldap server',
    'domain': 'fake ldap domain',
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
        db_api.share_access_delete(self.ctxt, share_access.id)
        self.assertRaises(exception.NotFound, db_api.share_access_get,
                          self.ctxt, share_access.id)


@ddt.ddt
class ShareAccessDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareAccessDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    @ddt.data(
        {'statuses': (constants.STATUS_ACTIVE, constants.STATUS_ACTIVE,
                      constants.STATUS_ACTIVE),
         'valid': constants.STATUS_ACTIVE},
        {'statuses': (constants.STATUS_ACTIVE, constants.STATUS_ACTIVE,
                      constants.STATUS_NEW),
         'valid': constants.STATUS_NEW},
        {'statuses': (constants.STATUS_ACTIVE, constants.STATUS_ACTIVE,
                      constants.STATUS_ERROR),
         'valid': constants.STATUS_ERROR},
        {'statuses': (constants.STATUS_DELETING, constants.STATUS_DELETED,
                      constants.STATUS_ERROR),
         'valid': constants.STATUS_ERROR},
        {'statuses': (constants.STATUS_DELETING, constants.STATUS_DELETED,
                      constants.STATUS_ACTIVE),
         'valid': constants.STATUS_DELETING},
        {'statuses': (constants.STATUS_DELETED, constants.STATUS_DELETED,
                      constants.STATUS_DELETED),
         'valid': constants.STATUS_DELETED},
    )
    @ddt.unpack
    def test_share_access_state(self, statuses, valid):
        share = db_utils.create_share()
        db_utils.create_share_instance(share_id=share['id'])
        db_utils.create_share_instance(share_id=share['id'])

        share = db_api.share_get(self.ctxt, share['id'])
        access = db_utils.create_access(state=constants.STATUS_ACTIVE,
                                        share_id=share['id'])

        for index, mapping in enumerate(access.instance_mappings):
            db_api.share_instance_access_update_state(
                self.ctxt, mapping['id'], statuses[index])

        access = db_api.share_access_get(self.ctxt, access['id'])

        self.assertEqual(valid, access.state)


@ddt.ddt
class ShareDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

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
        share_server = db_utils.create_share_server(
            share_network_id=share_network['id'])
        share = db_utils.create_share(share_server_id=share_server['id'],
                                      share_network_id=share_network['id'])

        actual_result = db_api.share_get_all_by_share_server(
            self.ctxt, share_server['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_filter_all_by_consistency_group(self):
        cg = db_utils.create_consistency_group()
        share = db_utils.create_share(consistency_group_id=cg['id'])

        actual_result = db_api.share_get_all_by_consistency_group_id(
            self.ctxt, cg['id'])

        self.assertEqual(1, len(actual_result))
        self.assertEqual(share['id'], actual_result[0].id)

    def test_share_instance_delete_with_share(self):
        share = db_utils.create_share()

        db_api.share_instance_delete(self.ctxt, share.instance['id'])

        self.assertRaises(exception.NotFound, db_api.share_get,
                          self.ctxt, share['id'])

    def test_share_instance_get(self):
        share = db_utils.create_share()

        instance = db_api.share_instance_get(self.ctxt, share.instance['id'])

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    def test_share_instance_get_all_by_consistency_group(self):
        cg = db_utils.create_consistency_group()
        db_utils.create_share(consistency_group_id=cg['id'])
        db_utils.create_share()

        instances = db_api.share_instances_get_all_by_consistency_group_id(
            self.ctxt, cg['id'])

        self.assertEqual(1, len(instances))
        instance = instances[0]

        self.assertEqual('share-%s' % instance['id'], instance['name'])

    @ddt.data('host', 'consistency_group_id')
    def test_share_get_all_sort_by_share_instance_fields(self, sort_key):
        shares = [db_utils.create_share(**{sort_key: n, 'size': 1})
                  for n in ('test1', 'test2')]

        actual_result = db_api.share_get_all(
            self.ctxt, sort_key=sort_key, sort_dir='desc')

        self.assertEqual(2, len(actual_result))
        self.assertEqual(shares[0]['id'], actual_result[1]['id'])


@ddt.ddt
class ConsistencyGroupDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ConsistencyGroupDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def test_consistency_group_create_with_share_type(self):
        fake_share_types = ["fake_share_type"]
        cg = db_utils.create_consistency_group(share_types=fake_share_types)
        cg = db_api.consistency_group_get(self.ctxt, cg['id'])

        self.assertEqual(1, len(cg['share_types']))

    def test_consistency_group_get(self):
        cg = db_utils.create_consistency_group()

        self.assertDictMatch(dict(cg),
                             dict(db_api.consistency_group_get(self.ctxt,
                                                               cg['id'])))

    def test_count_consistency_groups_in_share_network(self):
        share_network = db_utils.create_share_network()
        db_utils.create_consistency_group()
        db_utils.create_consistency_group(share_network_id=share_network['id'])

        count = db_api.count_consistency_groups_in_share_network(
            self.ctxt, share_network_id=share_network['id'])

        self.assertEqual(1, count)

    def test_consistency_group_get_all(self):
        expected_cg = db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all(self.ctxt, detailed=False)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertEqual(2, len(dict(cg).keys()))
        self.assertEqual(expected_cg['id'], cg['id'])
        self.assertEqual(expected_cg['name'], cg['name'])

    def test_consistency_group_get_all_with_detail(self):
        expected_cg = db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all(self.ctxt, detailed=True)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertDictMatch(dict(expected_cg), dict(cg))

    def test_consistency_group_get_all_by_host(self):
        fake_host = 'my_fake_host'
        expected_cg = db_utils.create_consistency_group(host=fake_host)
        db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all_by_host(self.ctxt, fake_host,
                                                       detailed=False)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertEqual(2, len(dict(cg).keys()))
        self.assertEqual(expected_cg['id'], cg['id'])
        self.assertEqual(expected_cg['name'], cg['name'])

    def test_consistency_group_get_all_by_host_with_details(self):
        fake_host = 'my_fake_host'
        expected_cg = db_utils.create_consistency_group(host=fake_host)
        db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all_by_host(self.ctxt,
                                                       fake_host,
                                                       detailed=True)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertDictMatch(dict(expected_cg), dict(cg))
        self.assertEqual(fake_host, cg['host'])

    def test_consistency_group_get_all_by_project(self):
        fake_project = 'fake_project'
        expected_cg = db_utils.create_consistency_group(
            project_id=fake_project)
        db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all_by_project(self.ctxt,
                                                          fake_project,
                                                          detailed=False)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertEqual(2, len(dict(cg).keys()))
        self.assertEqual(expected_cg['id'], cg['id'])
        self.assertEqual(expected_cg['name'], cg['name'])

    def test_consistency_group_get_all_by_share_server(self):
        fake_server = 123
        expected_cg = db_utils.create_consistency_group(
            share_server_id=fake_server)
        db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all_by_share_server(self.ctxt,
                                                               fake_server)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertEqual(expected_cg['id'], cg['id'])
        self.assertEqual(expected_cg['name'], cg['name'])

    def test_consistency_group_get_all_by_project_with_details(self):
        fake_project = 'fake_project'
        expected_cg = db_utils.create_consistency_group(
            project_id=fake_project)
        db_utils.create_consistency_group()

        cgs = db_api.consistency_group_get_all_by_project(self.ctxt,
                                                          fake_project,
                                                          detailed=True)

        self.assertEqual(1, len(cgs))
        cg = cgs[0]
        self.assertDictMatch(dict(expected_cg), dict(cg))
        self.assertEqual(fake_project, cg['project_id'])

    def test_consistency_group_update(self):
        fake_name = "my_fake_name"
        expected_cg = db_utils.create_consistency_group()
        expected_cg['name'] = fake_name

        db_api.consistency_group_update(self.ctxt,
                                        expected_cg['id'],
                                        {'name': fake_name})

        cg = db_api.consistency_group_get(self.ctxt, expected_cg['id'])
        self.assertEqual(fake_name, cg['name'])

    def test_consistency_group_destroy(self):
        cg = db_utils.create_consistency_group()
        db_api.consistency_group_get(self.ctxt, cg['id'])

        db_api.consistency_group_destroy(self.ctxt, cg['id'])

        self.assertRaises(exception.NotFound, db_api.consistency_group_get,
                          self.ctxt, cg['id'])

    def test_count_shares_in_consistency_group(self):
        cg = db_utils.create_consistency_group()
        db_utils.create_share(consistency_group_id=cg['id'])
        db_utils.create_share()

        count = db_api.count_shares_in_consistency_group(self.ctxt, cg['id'])

        self.assertEqual(1, count)

    def test_count_cgsnapshots_in_consistency_group(self):
        cg = db_utils.create_consistency_group()
        db_utils.create_cgsnapshot(cg['id'])
        db_utils.create_cgsnapshot(cg['id'])

        count = db_api.count_cgsnapshots_in_consistency_group(self.ctxt,
                                                              cg['id'])

        self.assertEqual(2, count)

    def test_cgsnapshot_get(self):
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])

        self.assertDictMatch(dict(cgsnap),
                             dict(db_api.cgsnapshot_get(self.ctxt,
                                                        cgsnap['id'])))

    def test_cgsnapshot_get_all(self):
        cg = db_utils.create_consistency_group()
        expected_cgsnap = db_utils.create_cgsnapshot(cg['id'])

        snaps = db_api.cgsnapshot_get_all(self.ctxt, detailed=False)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertEqual(2, len(dict(snap).keys()))
        self.assertEqual(expected_cgsnap['id'], snap['id'])
        self.assertEqual(expected_cgsnap['name'], snap['name'])

    def test_cgsnapshot_get_all_with_detail(self):
        cg = db_utils.create_consistency_group()
        expected_cgsnap = db_utils.create_cgsnapshot(cg['id'])

        snaps = db_api.cgsnapshot_get_all(self.ctxt, detailed=True)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertDictMatch(dict(expected_cgsnap), dict(snap))

    def test_cgsnapshot_get_all_by_project(self):
        fake_project = 'fake_project'
        cg = db_utils.create_consistency_group()
        expected_cgsnap = db_utils.create_cgsnapshot(cg['id'],
                                                     project_id=fake_project)

        snaps = db_api.cgsnapshot_get_all_by_project(self.ctxt,
                                                     fake_project,
                                                     detailed=False)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertEqual(2, len(dict(snap).keys()))
        self.assertEqual(expected_cgsnap['id'], snap['id'])
        self.assertEqual(expected_cgsnap['name'], snap['name'])

    def test_cgsnapshot_get_all_by_project_with_details(self):
        fake_project = 'fake_project'
        cg = db_utils.create_consistency_group()
        expected_cgsnap = db_utils.create_cgsnapshot(cg['id'],
                                                     project_id=fake_project)

        snaps = db_api.cgsnapshot_get_all_by_project(self.ctxt,
                                                     fake_project,
                                                     detailed=True)

        self.assertEqual(1, len(snaps))
        snap = snaps[0]
        self.assertDictMatch(dict(expected_cgsnap), dict(snap))
        self.assertEqual(fake_project, snap['project_id'])

    def test_cgsnapshot_update(self):
        fake_name = "my_fake_name"
        cg = db_utils.create_consistency_group()
        expected_cgsnap = db_utils.create_cgsnapshot(cg['id'])
        expected_cgsnap['name'] = fake_name

        db_api.cgsnapshot_update(self.ctxt, expected_cgsnap['id'],
                                 {'name': fake_name})

        cgsnap = db_api.cgsnapshot_get(self.ctxt, expected_cgsnap['id'])
        self.assertEqual(fake_name, cgsnap['name'])

    def test_cgsnapshot_destroy(self):
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])
        db_api.cgsnapshot_get(self.ctxt, cgsnap['id'])

        db_api.cgsnapshot_destroy(self.ctxt, cgsnap['id'])

        self.assertRaises(exception.NotFound, db_api.cgsnapshot_get,
                          self.ctxt, cgsnap['id'])

    def test_cgsnapshot_members_get_all(self):
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])
        expected_member = db_utils.create_cgsnapshot_member(cgsnap['id'])

        members = db_api.cgsnapshot_members_get_all(self.ctxt, cgsnap['id'])

        self.assertEqual(1, len(members))
        member = members[0]
        self.assertDictMatch(dict(expected_member), dict(member))

    def test_count_cgsnapshot_members_in_share(self):
        share = db_utils.create_share()
        share2 = db_utils.create_share()
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])
        db_utils.create_cgsnapshot_member(cgsnap['id'], share_id=share['id'])
        db_utils.create_cgsnapshot_member(cgsnap['id'], share_id=share2['id'])

        count = db_api.count_cgsnapshot_members_in_share(
            self.ctxt, share['id'])

        self.assertEqual(1, count)

    def test_cgsnapshot_members_get(self):
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])
        expected_member = db_utils.create_cgsnapshot_member(cgsnap['id'])

        member = db_api.cgsnapshot_member_get(self.ctxt,
                                              expected_member['id'])

        self.assertDictMatch(dict(expected_member), dict(member))

    def test_cgsnapshot_members_get_not_found(self):
        self.assertRaises(exception.CGSnapshotMemberNotFound,
                          db_api.cgsnapshot_member_get, self.ctxt, 'fake_id')

    def test_cgsnapshot_member_update(self):
        cg = db_utils.create_consistency_group()
        cgsnap = db_utils.create_cgsnapshot(cg['id'])
        expected_member = db_utils.create_cgsnapshot_member(cgsnap['id'])

        db_api.cgsnapshot_member_update(
            self.ctxt, expected_member['id'],
            {'status': constants.STATUS_AVAILABLE})

        member = db_api.cgsnapshot_member_get(self.ctxt, expected_member['id'])
        self.assertEqual(constants.STATUS_AVAILABLE, member['status'])


class ShareSnapshotDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(ShareSnapshotDatabaseAPITestCase, self).setUp()
        self.ctxt = context.get_admin_context()

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
        self.assertIn('share_id', instance_dict)


class ShareExportLocationsDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
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
        self.assertTrue(actual_result == update_locations)

    def test_update_string(self):
        share = db_utils.create_share()
        initial_location = 'fake1/1/'

        db_api.share_export_locations_update(self.ctxt, share.instance['id'],
                                             initial_location, False)
        actual_result = db_api.share_export_locations_get(self.ctxt,
                                                          share['id'])

        self.assertTrue(actual_result == [initial_location])

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
        super(self.__class__, self).setUp()
        self.ctxt = context.get_admin_context()
        self.share = db_utils.create_share()
        self.initial_locations = ['/fake/foo/', '/fake/bar', '/fake/quuz']
        db_api.share_export_locations_update(
            self.ctxt, self.share.instance['id'], self.initial_locations,
            delete=False)

    def _get_export_location_uuid_by_path(self, path):
        els = db_api.share_export_locations_get_by_share_id(
            self.ctxt, self.share.id)
        export_location_uuid = None
        for el in els:
            if el.path == path:
                export_location_uuid = el.uuid
        self.assertFalse(export_location_uuid is None)
        return export_location_uuid

    def test_get_export_locations_by_share_id(self):
        els = db_api.share_export_locations_get_by_share_id(
            self.ctxt, self.share.id)
        self.assertEqual(3, len(els))
        for path in self.initial_locations:
            self.assertTrue(any([path in el.path for el in els]))

    def test_get_export_locations_by_share_instance_id(self):
        els = db_api.share_export_locations_get_by_share_instance_id(
            self.ctxt, self.share.instance.id)
        self.assertEqual(3, len(els))
        for path in self.initial_locations:
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
        return ("fake@host", uuidutils.generate_uuid())

    @ddt.data({"details": {"foo": "bar", "tee": "too"},
               "valid": {"foo": "bar", "tee": "too"}},
              {"details": {"foo": "bar", "tee": ["test"]},
               "valid": {"foo": "bar", "tee": six.text_type(["test"])}})
    @ddt.unpack
    def test_update(self, details, valid):
        test_host, test_id = self._get_driver_test_data()

        initial_data = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)
        actual_data = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual({}, initial_data)
        self.assertEqual(valid, actual_data)

    def test_update_with_duplicate(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"tee": "too"}

        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(details, actual_result)

    def test_update_with_delete_existing(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"key1": "val1", "key2": "val2", "key3": "val3"}
        details_update = {"key1": "val1_upd", "key4": "new_val"}

        # Create new details
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details_update, delete_existing=True)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(details_update, actual_result)

    def test_get(self):
        test_host, test_id = self._get_driver_test_data()
        test_key = "foo"
        test_keys = [test_key, "tee"]
        details = {test_keys[0]: "val", test_keys[1]: "val", "mee": "foo"}
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)

        actual_result_all = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)
        actual_result_single_key = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id, test_key)
        actual_result_list = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id, test_keys)

        self.assertEqual(details, actual_result_all)
        self.assertEqual(details[test_key], actual_result_single_key)
        self.assertEqual(dict.fromkeys(test_keys, "val"), actual_result_list)

    def test_delete_single(self):
        test_host, test_id = self._get_driver_test_data()
        test_key = "foo"
        details = {test_key: "bar", "tee": "too"}
        valid_result = {"tee": "too"}
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)

        db_api.driver_private_data_delete(self.ctxt, test_host, test_id,
                                          test_key)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)

        self.assertEqual(valid_result, actual_result)

    def test_delete_all(self):
        test_host, test_id = self._get_driver_test_data()
        details = {"foo": "bar", "tee": "too"}
        db_api.driver_private_data_update(self.ctxt, test_host, test_id,
                                          details)

        db_api.driver_private_data_delete(self.ctxt, test_host, test_id)

        actual_result = db_api.driver_private_data_get(
            self.ctxt, test_host, test_id)

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
                              'neutron_net_id': 'fake net id',
                              'neutron_subnet_id': 'fake subnet id',
                              'project_id': self.fake_context.project_id,
                              'user_id': 'fake_user_id',
                              'network_type': 'vlan',
                              'segmentation_id': 1000,
                              'cidr': '10.0.0.0/24',
                              'ip_version': 4,
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
        result2 = db_api.share_network_create(self.fake_context,
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
        self._check_fields(expected=dict(six.iteritems(result_update)),
                           actual=dict(six.iteritems(result_get)))

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
                                       'neutron_subnet_id': fake_id})
            share_networks.append(share_network_dict)
            db_api.share_network_create(self.fake_context, share_network_dict)
            index += 1

        result = db_api.share_network_get_all(self.fake_context)

        self.assertEqual(len(share_networks), len(result))
        for index, net in enumerate(share_networks):
            self._check_fields(expected=net, actual=result[index])

    def test_get_all_by_project(self):
        share_nw_dict2 = dict(self.share_nw_dict)
        share_nw_dict2['id'] = 'fake share nw id2'
        share_nw_dict2['project_id'] = 'fake project 2'
        share_nw_dict2['neutron_subnet_id'] = 'fake subnet id2'
        db_api.share_network_create(self.fake_context, self.share_nw_dict)
        db_api.share_network_create(self.fake_context, share_nw_dict2)

        result = db_api.share_network_get_all_by_project(
            self.fake_context,
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

        result = db_api.model_query(
            self.fake_context,
            models.ShareNetworkSecurityServiceAssociation).\
            filter_by(security_service_id=security_dict1['id']).\
            filter_by(share_network_id=self.share_nw_dict['id']).first()

        self.assertTrue(result is not None)

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

        result = db_api.model_query(
            self.fake_context,
            models.ShareNetworkSecurityServiceAssociation).\
            filter_by(security_service_id=security_dict1['id']).\
            filter_by(share_network_id=self.share_nw_dict['id']).first()

        self.assertTrue(result is None)

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


class ShareServerDatabaseAPITestCase(test.TestCase):

    def setUp(self):
        super(ShareServerDatabaseAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id',
                                           is_admin=True)

    def test_share_server_get(self):
        expected = db_utils.create_share_server()
        server = db_api.share_server_get(self.ctxt, expected['id'])
        self.assertEqual(expected['id'], server['id'])
        self.assertEqual(expected.share_network_id, server.share_network_id)
        self.assertEqual(expected.host, server.host)
        self.assertEqual(expected.status, server.status)

    def test_get_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_get, self.ctxt, fake_id)

    def test_create(self):
        server = db_utils.create_share_server()
        self.assertTrue(server['id'])
        self.assertEqual(server.share_network_id, server['share_network_id'])
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
        update = {
            'share_network_id': 'update_net',
            'host': 'update_host',
            'status': constants.STATUS_ACTIVE,
        }
        server = db_utils.create_share_server()
        updated_server = db_api.share_server_update(self.ctxt, server['id'],
                                                    update)
        self.assertEqual(server['id'], updated_server['id'])
        self.assertEqual(update['share_network_id'],
                         updated_server.share_network_id)
        self.assertEqual(update['host'], updated_server.host)
        self.assertEqual(update['status'], updated_server.status)

    def test_update_not_found(self):
        fake_id = 'FAKE_UUID'
        self.assertRaises(exception.ShareServerNotFound,
                          db_api.share_server_update,
                          self.ctxt, fake_id, {})

    def test_get_all_by_host_and_share_net_valid(self):
        valid = {
            'share_network_id': '1',
            'host': 'host1',
            'status': constants.STATUS_ACTIVE,
        }
        invalid = {
            'share_network_id': '1',
            'host': 'host1',
            'status': constants.STATUS_ERROR,
        }
        other = {
            'share_network_id': '2',
            'host': 'host2',
            'status': constants.STATUS_ACTIVE,
        }
        valid = db_utils.create_share_server(**valid)
        db_utils.create_share_server(**invalid)
        db_utils.create_share_server(**other)

        servers = db_api.share_server_get_all_by_host_and_share_net_valid(
            self.ctxt,
            host='host1',
            share_net_id='1')
        self.assertEqual(valid['id'], servers[0]['id'])

    def test_get_all_by_host_and_share_net_not_found(self):
        self.assertRaises(
            exception.ShareServerNotFound,
            db_api.share_server_get_all_by_host_and_share_net_valid,
            self.ctxt, host='fake', share_net_id='fake'
        )

    def test_get_all(self):
        srv1 = {
            'share_network_id': '1',
            'host': 'host1',
            'status': constants.STATUS_ACTIVE,
        }
        srv2 = {
            'share_network_id': '1',
            'host': 'host1',
            'status': constants.STATUS_ERROR,
        }
        srv3 = {
            'share_network_id': '2',
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

        self.assertDictMatch(
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
            'share_network_id': 'fake-share-net-id',
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
        self.assertEqual(values['share_network_id'], server.share_network_id)
        self.assertEqual(values['host'], server.host)
        self.assertEqual(values['status'], server.status)
        self.assertDictMatch(server['backend_details'], details)
        self.assertTrue('backend_details' in server.to_dict())

    def test_delete_with_details(self):
        server = db_utils.create_share_server(backend_details={
            'value1': '1',
            'value2': '2',
        })

        num_records = len(db_api.share_server_get_all(self.ctxt))
        db_api.share_server_delete(self.ctxt, server['id'])
        self.assertEqual(num_records - 1,
                         len(db_api.share_server_get_all(self.ctxt)))


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
    def test_ensure_availability_zone_exists_invalid(self, test_values):
        session = db_api.get_session()

        self.assertRaises(ValueError, db_api.ensure_availability_zone_exists,
                          self.ctxt, test_values, session)

    def test_az_get(self):
        az_name = 'test_az'
        az = db_api.availability_zone_create_if_not_exist(self.ctxt, az_name)

        az_by_id = db_api.availability_zone_get(self.ctxt, az['id'])
        az_by_name = db_api.availability_zone_get(self.ctxt, az_name)

        self.assertEqual(az_name, az_by_id['name'])
        self.assertEqual(az_name, az_by_name['name'])
        self.assertEqual(az['id'], az_by_id['id'])
        self.assertEqual(az['id'], az_by_name['id'])

    def test_az_get_all(self):
        db_api.availability_zone_create_if_not_exist(self.ctxt, 'test1')
        db_api.availability_zone_create_if_not_exist(self.ctxt, 'test2')
        db_api.availability_zone_create_if_not_exist(self.ctxt, 'test3')
        db_api.service_create(self.ctxt, {'availability_zone': 'test2'})

        actual_result = db_api.availability_zone_get_all(self.ctxt)

        self.assertEqual(1, len(actual_result))
        self.assertEqual('test2', actual_result[0]['name'])
