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

"""
Tests data for database migrations.

All database migrations with data manipulation
(like moving data from column to the table) should have data check class:

@map_to_migration('1f0bd302c1a6') # Revision of checked db migration
class FooMigrationChecks(BaseMigrationChecks):
   def setup_upgrade_data(self, engine):
       ...

    def check_upgrade(self, engine, data):
       ...

    def check_downgrade(self, engine):
       ...

See BaseMigrationChecks class for more information.
"""

import abc
import datetime

from oslo_db import exception as oslo_db_exc
from oslo_utils import uuidutils
import six
from sqlalchemy import exc as sa_exc

from manila.common import constants
from manila.db.migrations import utils


class DbMigrationsData(object):

    migration_mappings = {}

    methods_mapping = {
        'pre': 'setup_upgrade_data',
        'check': 'check_upgrade',
        'post': 'check_downgrade',
    }

    def __getattr__(self, item):
        parts = item.split('_')

        is_mapping_method = (
            len(parts) > 2 and parts[0] == ''
            and parts[1] in self.methods_mapping
        )

        if not is_mapping_method:
            return super(DbMigrationsData, self).__getattribute__(item)

        check_obj = self.migration_mappings.get(parts[-1], None)

        if check_obj is None:
            raise AttributeError

        check_obj.set_test_case(self)

        return getattr(check_obj, self.methods_mapping.get(parts[1]))


def map_to_migration(revision):
    def decorator(cls):
        DbMigrationsData.migration_mappings[revision] = cls()
        return cls
    return decorator


class BaseMigrationChecks(object):

    six.add_metaclass(abc.ABCMeta)

    def __init__(self):
        self.test_case = None

    def set_test_case(self, test_case):
        self.test_case = test_case

    @abc.abstractmethod
    def setup_upgrade_data(self, engine):
        """This method should be used to insert test data for migration.

        :param engine: SQLAlchemy engine
        :return: any data which will be passed to 'check_upgrade' as 'data' arg
        """

    @abc.abstractmethod
    def check_upgrade(self, engine, data):
        """This method should be used to do assertions after upgrade method.

        To perform assertions use 'self.test_case' instance property:
        self.test_case.assertTrue(True)

        :param engine: SQLAlchemy engine
        :param data: data returned by 'setup_upgrade_data'
        """

    @abc.abstractmethod
    def check_downgrade(self, engine):
        """This method should be used to do assertions after downgrade method.

        To perform assertions use 'self.test_case' instance property:
        self.test_case.assertTrue(True)

        :param engine: SQLAlchemy engine
        """


def fake_share(**kwargs):
    share = {
        'id': uuidutils.generate_uuid(),
        'display_name': 'fake_share',
        'display_description': 'my fake share',
        'snapshot_id': uuidutils.generate_uuid(),
        'share_proto': 'nfs',
        'is_public': True,
        'size': 1,
        'deleted': 'False',
        'share_proto': 'fake_proto',
        'user_id': uuidutils.generate_uuid(),
        'project_id': uuidutils.generate_uuid(),
        'snapshot_support': True,
        'task_state': None,
    }
    share.update(kwargs)
    return share


def fake_instance(share_id=None, **kwargs):
    instance = {
        'id': uuidutils.generate_uuid(),
        'share_id': share_id or uuidutils.generate_uuid(),
        'deleted': 'False',
        'host': 'openstack@BackendZ#PoolA',
        'status': 'available',
        'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
        'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
        'terminated_at': None,
        'access_rules_status': 'active',
    }
    instance.update(kwargs)
    return instance


@map_to_migration('38e632621e5a')
class ShareTypeMigrationChecks(BaseMigrationChecks):
    def _get_fake_data(self):
        extra_specs = []
        self.share_type_ids = []
        volume_types = [
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'vol-type-A',
            },
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'vol-type-B',
            },
        ]
        for idx, volume_type in enumerate(volume_types):
            extra_specs.append({
                'volume_type_id': volume_type['id'],
                'key': 'foo',
                'value': 'bar%s' % idx,
                'deleted': False,
            })
            extra_specs.append({
                'volume_type_id': volume_type['id'],
                'key': 'xyzzy',
                'value': 'spoon_%s' % idx,
                'deleted': False,
            })
            self.share_type_ids.append(volume_type['id'])
        return volume_types, extra_specs

    def setup_upgrade_data(self, engine):
        (self.volume_types, self.extra_specs) = self._get_fake_data()

        volume_types_table = utils.load_table('volume_types', engine)
        engine.execute(volume_types_table.insert(self.volume_types))
        extra_specs_table = utils.load_table('volume_type_extra_specs',
                                             engine)
        engine.execute(extra_specs_table.insert(self.extra_specs))

    def check_upgrade(self, engine, data):
        # Verify table transformations
        share_types_table = utils.load_table('share_types', engine)
        share_types_specs_table = utils.load_table(
            'share_type_extra_specs', engine)
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    'volume_types', engine)
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    'volume_type_extra_specs', engine)

        # Verify presence of data
        share_type_ids = [
            st['id'] for st in engine.execute(share_types_table.select())
            if st['id'] in self.share_type_ids
        ]
        self.test_case.assertEqual(sorted(self.share_type_ids),
                                   sorted(share_type_ids))
        extra_specs = [
            {'type': es['share_type_id'], 'key': es['spec_key']}
            for es in engine.execute(share_types_specs_table.select())
            if es['share_type_id'] in self.share_type_ids
        ]
        self.test_case.assertEqual(4, len(extra_specs))

    def check_downgrade(self, engine):
        # Verify table transformations
        volume_types_table = utils.load_table('volume_types', engine)
        volume_types_specs_table = utils.load_table(
            'volume_type_extra_specs', engine)
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    'share_types', engine)
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    'share_type_extra_specs', engine)

        # Verify presence of data
        volume_type_ids = [
            vt['id'] for vt in engine.execute(volume_types_table.select())
            if vt['id'] in self.share_type_ids
        ]
        self.test_case.assertEqual(sorted(self.share_type_ids),
                                   sorted(volume_type_ids))
        extra_specs = [
            {'type': es['volume_type_id'], 'key': es['key']}
            for es in engine.execute(volume_types_specs_table.select())
            if es['volume_type_id'] in self.share_type_ids
        ]
        self.test_case.assertEqual(4, len(extra_specs))


@map_to_migration('5077ffcc5f1c')
class ShareInstanceMigrationChecks(BaseMigrationChecks):
    def _prepare_fake_data(self):
        time = datetime.datetime(2017, 1, 12, 12, 12, 12)
        self.share = {
            'id': uuidutils.generate_uuid(),
            'host': 'fake_host',
            'status': 'fake_status',
            'scheduled_at': time,
            'launched_at': time,
            'terminated_at': time,
            'availability_zone': 'fake_az'}
        self.share_snapshot = {
            'id': uuidutils.generate_uuid(),
            'status': 'fake_status',
            'share_id': self.share['id'],
            'progress': 'fake_progress'}
        self.share_export_location = {
            'id': 1001,
            'share_id': self.share['id']}

    def setup_upgrade_data(self, engine):
        self._prepare_fake_data()
        share_table = utils.load_table('shares', engine)
        engine.execute(share_table.insert(self.share))
        snapshot_table = utils.load_table('share_snapshots', engine)
        engine.execute(snapshot_table.insert(self.share_snapshot))
        el_table = utils.load_table('share_export_locations', engine)
        engine.execute(el_table.insert(self.share_export_location))

    def check_upgrade(self, engine, data):
        share_table = utils.load_table('shares', engine)
        s_instance_table = utils.load_table('share_instances', engine)
        ss_instance_table = utils.load_table('share_snapshot_instances',
                                             engine)
        snapshot_table = utils.load_table('share_snapshots', engine)
        instance_el_table = utils.load_table('share_instance_export_locations',
                                             engine)
        # Check shares table
        for column in ['host', 'status', 'scheduled_at', 'launched_at',
                       'terminated_at', 'share_network_id', 'share_server_id',
                       'availability_zone']:
            rows = engine.execute(share_table.select())
            for row in rows:
                self.test_case.assertFalse(hasattr(row, column))

        # Check share instance table
        s_instance_record = engine.execute(s_instance_table.select().where(
            s_instance_table.c.share_id == self.share['id'])).first()
        self.test_case.assertTrue(s_instance_record is not None)
        for column in ['host', 'status', 'scheduled_at', 'launched_at',
                       'terminated_at', 'availability_zone']:
            self.test_case.assertEqual(self.share[column],
                                       s_instance_record[column])

        # Check snapshot table
        for column in ['status', 'progress']:
            rows = engine.execute(snapshot_table.select())
            for row in rows:
                self.test_case.assertFalse(hasattr(row, column))

        # Check snapshot instance table
        ss_instance_record = engine.execute(ss_instance_table.select().where(
            ss_instance_table.c.snapshot_id == self.share_snapshot['id'])
        ).first()
        self.test_case.assertEqual(s_instance_record['id'],
                                   ss_instance_record['share_instance_id'])
        for column in ['status', 'progress']:
            self.test_case.assertEqual(self.share_snapshot[column],
                                       ss_instance_record[column])

        # Check share export location table
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, 'share_export_locations', engine)

        # Check share instance export location table
        el_record = engine.execute(instance_el_table.select().where(
            instance_el_table.c.share_instance_id == s_instance_record['id'])
        ).first()
        self.test_case.assertFalse(el_record is None)
        self.test_case.assertTrue(hasattr(el_record, 'share_instance_id'))
        self.test_case.assertFalse(hasattr(el_record, 'share_id'))

    def check_downgrade(self, engine):
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, 'share_snapshot_instances', engine)
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, 'share_instances', engine)
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, 'share_instance_export_locations', engine)
        share_table = utils.load_table('shares', engine)
        snapshot_table = utils.load_table('share_snapshots', engine)
        share_el_table = utils.load_table('share_export_locations',
                                          engine)
        for column in ['host', 'status', 'scheduled_at', 'launched_at',
                       'terminated_at', 'share_network_id', 'share_server_id',
                       'availability_zone']:
            rows = engine.execute(share_table.select())
            for row in rows:
                self.test_case.assertTrue(hasattr(row, column))

        for column in ['status', 'progress']:
            rows = engine.execute(snapshot_table.select())
            for row in rows:
                self.test_case.assertTrue(hasattr(row, column))
        rows = engine.execute(share_el_table.select())
        for row in rows:
            self.test_case.assertFalse(hasattr(row, 'share_instance_id'))
            self.test_case.assertTrue(
                hasattr(row, 'share_id'))


@map_to_migration('1f0bd302c1a6')
class AvailabilityZoneMigrationChecks(BaseMigrationChecks):

    valid_az_names = ('az1', 'az2')

    def _get_service_data(self, options):
        base_dict = {
            'binary': 'manila-share',
            'topic': 'share',
            'disabled': False,
            'report_count': '100',
        }
        base_dict.update(options)
        return base_dict

    def setup_upgrade_data(self, engine):
        service_fixture = [
            self._get_service_data(
                {'deleted': 0, 'host': 'fake1', 'availability_zone': 'az1'}
            ),
            self._get_service_data(
                {'deleted': 0, 'host': 'fake2', 'availability_zone': 'az1'}
            ),
            self._get_service_data(
                {'deleted': 1, 'host': 'fake3', 'availability_zone': 'az2'}
            ),
        ]

        services_table = utils.load_table('services', engine)

        for fixture in service_fixture:
            engine.execute(services_table.insert(fixture))

    def check_upgrade(self, engine, _):
        az_table = utils.load_table('availability_zones', engine)

        for az in engine.execute(az_table.select()):
            self.test_case.assertTrue(uuidutils.is_uuid_like(az.id))
            self.test_case.assertIn(az.name, self.valid_az_names)
            self.test_case.assertEqual('False', az.deleted)

        services_table = utils.load_table('services', engine)
        for service in engine.execute(services_table.select()):
            self.test_case.assertTrue(
                uuidutils.is_uuid_like(service.availability_zone_id)
            )

    def check_downgrade(self, engine):
        services_table = utils.load_table('services', engine)
        for service in engine.execute(services_table.select()):
            self.test_case.assertIn(
                service.availability_zone, self.valid_az_names
            )


@map_to_migration('dda6de06349')
class ShareInstanceExportLocationMetadataChecks(BaseMigrationChecks):
    el_table_name = 'share_instance_export_locations'
    elm_table_name = 'share_instance_export_locations_metadata'

    def setup_upgrade_data(self, engine):
        # Setup shares
        share_fixture = [{'id': 'foo_share_id'}, {'id': 'bar_share_id'}]
        share_table = utils.load_table('shares', engine)
        for fixture in share_fixture:
            engine.execute(share_table.insert(fixture))

        # Setup share instances
        si_fixture = [
            {'id': 'foo_share_instance_id_oof',
             'share_id': share_fixture[0]['id']},
            {'id': 'bar_share_instance_id_rab',
             'share_id': share_fixture[1]['id']},
        ]
        si_table = utils.load_table('share_instances', engine)
        for fixture in si_fixture:
            engine.execute(si_table.insert(fixture))

        # Setup export locations
        el_fixture = [
            {'id': 1, 'path': '/1', 'share_instance_id': si_fixture[0]['id']},
            {'id': 2, 'path': '/2', 'share_instance_id': si_fixture[1]['id']},
        ]
        el_table = utils.load_table(self.el_table_name, engine)
        for fixture in el_fixture:
            engine.execute(el_table.insert(fixture))

    def check_upgrade(self, engine, data):
        el_table = utils.load_table(
            'share_instance_export_locations', engine)
        for el in engine.execute(el_table.select()):
            self.test_case.assertTrue(hasattr(el, 'is_admin_only'))
            self.test_case.assertTrue(hasattr(el, 'uuid'))
            self.test_case.assertEqual(False, el.is_admin_only)
            self.test_case.assertTrue(uuidutils.is_uuid_like(el.uuid))

        # Write export location metadata
        el_metadata = [
            {'key': 'foo_key', 'value': 'foo_value', 'export_location_id': 1},
            {'key': 'bar_key', 'value': 'bar_value', 'export_location_id': 2},
        ]
        elm_table = utils.load_table(self.elm_table_name, engine)
        engine.execute(elm_table.insert(el_metadata))

        # Verify values of written metadata
        for el_meta_datum in el_metadata:
            el_id = el_meta_datum['export_location_id']
            records = engine.execute(elm_table.select().where(
                elm_table.c.export_location_id == el_id))
            self.test_case.assertEqual(1, records.rowcount)
            record = records.first()

            expected_keys = (
                'id', 'created_at', 'updated_at', 'deleted_at', 'deleted',
                'export_location_id', 'key', 'value',
            )
            self.test_case.assertEqual(len(expected_keys), len(record.keys()))
            for key in expected_keys:
                self.test_case.assertIn(key, record.keys())

            for k, v in el_meta_datum.items():
                self.test_case.assertTrue(hasattr(record, k))
                self.test_case.assertEqual(v, getattr(record, k))

    def check_downgrade(self, engine):
        el_table = utils.load_table(
            'share_instance_export_locations', engine)
        for el in engine.execute(el_table.select()):
            self.test_case.assertFalse(hasattr(el, 'is_admin_only'))
            self.test_case.assertFalse(hasattr(el, 'uuid'))
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, self.elm_table_name, engine)


@map_to_migration('344c1ac4747f')
class AccessRulesStatusMigrationChecks(BaseMigrationChecks):

    def _get_instance_data(self, data):
        base_dict = {}
        base_dict.update(data)
        return base_dict

    def setup_upgrade_data(self, engine):

        share_table = utils.load_table('shares', engine)

        share = {
            'id': 1,
            'share_proto': "NFS",
            'size': 0,
            'snapshot_id': None,
            'user_id': 'fake',
            'project_id': 'fake',
        }

        engine.execute(share_table.insert(share))

        rules1 = [
            {'id': 'r1', 'share_instance_id': 1, 'state': 'active',
             'deleted': 'False'},
            {'id': 'r2', 'share_instance_id': 1, 'state': 'active',
             'deleted': 'False'},
            {'id': 'r3', 'share_instance_id': 1, 'state': 'deleting',
             'deleted': 'False'},
        ]
        rules2 = [
            {'id': 'r4', 'share_instance_id': 2, 'state': 'active',
             'deleted': 'False'},
            {'id': 'r5', 'share_instance_id': 2, 'state': 'error',
             'deleted': 'False'},
        ]

        rules3 = [
            {'id': 'r6', 'share_instance_id': 3, 'state': 'new',
             'deleted': 'False'},
        ]

        instance_fixtures = [
            {'id': 1, 'deleted': 'False', 'host': 'fake1', 'share_id': 1,
             'status': 'available', 'rules': rules1},
            {'id': 2, 'deleted': 'False', 'host': 'fake2', 'share_id': 1,
             'status': 'available', 'rules': rules2},
            {'id': 3, 'deleted': 'False', 'host': 'fake3', 'share_id': 1,
             'status': 'available', 'rules': rules3},
            {'id': 4, 'deleted': 'False', 'host': 'fake4', 'share_id': 1,
             'status': 'deleting', 'rules': []},
        ]

        share_instances_table = utils.load_table('share_instances', engine)
        share_instances_rules_table = utils.load_table(
            'share_instance_access_map', engine)

        for fixture in instance_fixtures:
            rules = fixture.pop('rules')
            engine.execute(share_instances_table.insert(fixture))

            for rule in rules:
                engine.execute(share_instances_rules_table.insert(rule))

    def check_upgrade(self, engine, _):
        instances_table = utils.load_table('share_instances', engine)

        valid_statuses = {
            '1': 'active',
            '2': 'error',
            '3': 'out_of_sync',
            '4': None,
        }

        instances = engine.execute(instances_table.select().where(
            instances_table.c.id in valid_statuses.keys()))

        for instance in instances:
            self.test_case.assertEqual(valid_statuses[instance['id']],
                                       instance['access_rules_status'])

    def check_downgrade(self, engine):
        share_instances_rules_table = utils.load_table(
            'share_instance_access_map', engine)
        share_instance_rules_to_check = engine.execute(
            share_instances_rules_table.select().where(
                share_instances_rules_table.c.id.in_(('1', '2', '3', '4'))))

        valid_statuses = {
            '1': 'active',
            '2': 'error',
            '3': 'error',
            '4': None,
        }

        for rule in share_instance_rules_to_check:
            valid_state = valid_statuses[rule['share_instance_id']]
            self.test_case.assertEqual(valid_state, rule['state'])


@map_to_migration('293fac1130ca')
class ShareReplicationMigrationChecks(BaseMigrationChecks):

    valid_share_display_names = ('FAKE_SHARE_1', 'FAKE_SHARE_2',
                                 'FAKE_SHARE_3')
    valid_share_ids = []
    valid_replication_types = ('writable', 'readable', 'dr')

    def _load_tables_and_get_data(self, engine):
        share_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)

        shares = engine.execute(
            share_table.select().where(share_table.c.id.in_(
                self.valid_share_ids))
        ).fetchall()
        share_instances = engine.execute(share_instances_table.select().where(
            share_instances_table.c.share_id.in_(self.valid_share_ids))
        ).fetchall()

        return shares, share_instances

    def setup_upgrade_data(self, engine):

        shares_data = []
        instances_data = []
        self.valid_share_ids = []

        for share_display_name in self.valid_share_display_names:
            share_ref = fake_share(display_name=share_display_name)
            shares_data.append(share_ref)
            instances_data.append(fake_instance(share_id=share_ref['id']))

        shares_table = utils.load_table('shares', engine)

        for share in shares_data:
            self.valid_share_ids.append(share['id'])
            engine.execute(shares_table.insert(share))

        shares_instances_table = utils.load_table('share_instances', engine)

        for share_instance in instances_data:
            engine.execute(shares_instances_table.insert(share_instance))

    def check_upgrade(self, engine, _):
        shares, share_instances = self._load_tables_and_get_data(engine)
        share_ids = [share['id'] for share in shares]
        share_instance_share_ids = [share_instance['share_id'] for
                                    share_instance in share_instances]

        # Assert no data is lost
        for sid in self.valid_share_ids:
            self.test_case.assertIn(sid, share_ids)
            self.test_case.assertIn(sid, share_instance_share_ids)

        for share in shares:
            self.test_case.assertIn(share['display_name'],
                                    self.valid_share_display_names)
            self.test_case.assertEqual('False', share.deleted)
            self.test_case.assertTrue(hasattr(share, 'replication_type'))

        for share_instance in share_instances:
            self.test_case.assertTrue(hasattr(share_instance, 'replica_state'))

    def check_downgrade(self, engine):
        shares, share_instances = self._load_tables_and_get_data(engine)
        share_ids = [share['id'] for share in shares]
        share_instance_share_ids = [share_instance['share_id'] for
                                    share_instance in share_instances]
        # Assert no data is lost
        for sid in self.valid_share_ids:
            self.test_case.assertIn(sid, share_ids)
            self.test_case.assertIn(sid, share_instance_share_ids)

        for share in shares:
            self.test_case.assertEqual('False', share.deleted)
            self.test_case.assertIn(share.display_name,
                                    self.valid_share_display_names)
            self.test_case.assertFalse(hasattr(share, 'replication_type'))

        for share_instance in share_instances:
            self.test_case.assertEqual('False', share_instance.deleted)
            self.test_case.assertIn(share_instance.share_id,
                                    self.valid_share_ids)
            self.test_case.assertFalse(
                hasattr(share_instance, 'replica_state'))


@map_to_migration('5155c7077f99')
class NetworkAllocationsNewLabelColumnChecks(BaseMigrationChecks):
    table_name = 'network_allocations'
    ids = ['fake_network_allocation_id_%d' % i for i in (1, 2, 3)]

    def setup_upgrade_data(self, engine):
        user_id = 'user_id'
        project_id = 'project_id'
        share_server_id = 'foo_share_server_id'

        # Create share network
        share_network_data = {
            'id': 'foo_share_network_id',
            'user_id': user_id,
            'project_id': project_id,
        }
        sn_table = utils.load_table('share_networks', engine)
        engine.execute(sn_table.insert(share_network_data))

        # Create share server
        share_server_data = {
            'id': share_server_id,
            'share_network_id': share_network_data['id'],
            'host': 'fake_host',
            'status': 'active',
        }
        ss_table = utils.load_table('share_servers', engine)
        engine.execute(ss_table.insert(share_server_data))

        # Create network allocations
        network_allocations = [
            {'id': self.ids[0],
             'share_server_id': share_server_id,
             'ip_address': '1.1.1.1'},
            {'id': self.ids[1],
             'share_server_id': share_server_id,
             'ip_address': '2.2.2.2'},
        ]
        na_table = utils.load_table(self.table_name, engine)
        for network_allocation in network_allocations:
            engine.execute(na_table.insert(network_allocation))

    def check_upgrade(self, engine, data):
        na_table = utils.load_table(self.table_name, engine)
        for na in engine.execute(na_table.select()):
            self.test_case.assertTrue(hasattr(na, 'label'))
            self.test_case.assertEqual(na.label, 'user')

        # Create admin network allocation
        network_allocations = [
            {'id': self.ids[2],
             'share_server_id': na.share_server_id,
             'ip_address': '3.3.3.3',
             'label': 'admin',
             'network_type': 'vlan',
             'segmentation_id': 1005,
             'ip_version': 4,
             'cidr': '240.0.0.0/16'},
        ]
        engine.execute(na_table.insert(network_allocations))

        # Select admin network allocations
        for na in engine.execute(
                na_table.select().where(na_table.c.label == 'admin')):
            self.test_case.assertTrue(hasattr(na, 'label'))
            self.test_case.assertEqual('admin', na.label)
            for col_name in ('network_type', 'segmentation_id', 'ip_version',
                             'cidr'):
                self.test_case.assertTrue(hasattr(na, col_name))
                self.test_case.assertEqual(
                    network_allocations[0][col_name], getattr(na, col_name))

    def check_downgrade(self, engine):
        na_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(na_table.select())
        self.test_case.assertTrue(db_result.rowcount >= len(self.ids))
        for na in db_result:
            for col_name in ('label', 'network_type', 'segmentation_id',
                             'ip_version', 'cidr'):
                self.test_case.assertFalse(hasattr(na, col_name))


@map_to_migration('eb6d5544cbbd')
class ShareSnapshotInstanceNewProviderLocationColumnChecks(
        BaseMigrationChecks):
    table_name = 'share_snapshot_instances'

    def setup_upgrade_data(self, engine):
        # Setup shares
        share_data = {'id': 'new_share_id'}
        s_table = utils.load_table('shares', engine)
        engine.execute(s_table.insert(share_data))

        # Setup share instances
        share_instance_data = {
            'id': 'new_share_instance_id',
            'share_id': share_data['id']
        }
        si_table = utils.load_table('share_instances', engine)
        engine.execute(si_table.insert(share_instance_data))

        # Setup share snapshots
        share_snapshot_data = {
            'id': 'new_snapshot_id',
            'share_id': share_data['id']}
        snap_table = utils.load_table('share_snapshots', engine)
        engine.execute(snap_table.insert(share_snapshot_data))

        # Setup snapshot instances
        snapshot_instance_data = {
            'id': 'new_snapshot_instance_id',
            'snapshot_id': share_snapshot_data['id'],
            'share_instance_id': share_instance_data['id']
        }
        snap_i_table = utils.load_table('share_snapshot_instances', engine)
        engine.execute(snap_i_table.insert(snapshot_instance_data))

    def check_upgrade(self, engine, data):
        ss_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(ss_table.select().where(
            ss_table.c.id == 'new_snapshot_instance_id'))
        self.test_case.assertTrue(db_result.rowcount > 0)
        for ss in db_result:
            self.test_case.assertTrue(hasattr(ss, 'provider_location'))
            self.test_case.assertEqual('new_snapshot_id', ss.snapshot_id)

    def check_downgrade(self, engine):
        ss_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(ss_table.select().where(
            ss_table.c.id == 'new_snapshot_instance_id'))
        self.test_case.assertTrue(db_result.rowcount > 0)
        for ss in db_result:
            self.test_case.assertFalse(hasattr(ss, 'provider_location'))
            self.test_case.assertEqual('new_snapshot_id', ss.snapshot_id)


@map_to_migration('221a83cfd85b')
class ShareNetworksFieldLengthChecks(BaseMigrationChecks):
    def setup_upgrade_data(self, engine):
        user_id = '123456789123456789'
        project_id = 'project_id'

        # Create share network data
        share_network_data = {
            'id': 'foo_share_network_id_2',
            'user_id': user_id,
            'project_id': project_id,
        }
        sn_table = utils.load_table('share_networks', engine)
        engine.execute(sn_table.insert(share_network_data))

        # Create security_service data
        security_services_data = {
            'id': 'foo_security_services_id',
            'type': 'foo_type',
            'project_id': project_id
        }
        ss_table = utils.load_table('security_services', engine)
        engine.execute(ss_table.insert(security_services_data))

    def _check_length_for_table_columns(self, table_name, engine,
                                        cols, length):
        table = utils.load_table(table_name, engine)
        db_result = engine.execute(table.select())
        self.test_case.assertTrue(db_result.rowcount > 0)

        for col in cols:
            self.test_case.assertEqual(table.columns.get(col).type.length,
                                       length)

    def check_upgrade(self, engine, data):
        self._check_length_for_table_columns('share_networks', engine,
                                             ('user_id', 'project_id'), 255)

        self._check_length_for_table_columns('security_services', engine,
                                             ('project_id',), 255)

    def check_downgrade(self, engine):
        self._check_length_for_table_columns('share_networks', engine,
                                             ('user_id', 'project_id'), 36)

        self._check_length_for_table_columns('security_services', engine,
                                             ('project_id',), 36)


@map_to_migration('fdfb668d19e1')
class NewGatewayColumnChecks(BaseMigrationChecks):
    na_table_name = 'network_allocations'
    sn_table_name = 'share_networks'
    na_ids = ['network_allocation_id_fake_%d' % i for i in (1, 2, 3)]
    sn_ids = ['share_network_id_fake_%d' % i for i in (1, 2)]

    def setup_upgrade_data(self, engine):
        user_id = 'user_id'
        project_id = 'project_id'
        share_server_id = 'share_server_id_foo'

        # Create share network
        share_network_data = {
            'id': self.sn_ids[0],
            'user_id': user_id,
            'project_id': project_id,
        }
        sn_table = utils.load_table(self.sn_table_name, engine)
        engine.execute(sn_table.insert(share_network_data))

        # Create share server
        share_server_data = {
            'id': share_server_id,
            'share_network_id': share_network_data['id'],
            'host': 'fake_host',
            'status': 'active',
        }
        ss_table = utils.load_table('share_servers', engine)
        engine.execute(ss_table.insert(share_server_data))

        # Create network allocations
        network_allocations = [
            {
                'id': self.na_ids[0],
                'share_server_id': share_server_id,
                'ip_address': '1.1.1.1',
            },
            {
                'id': self.na_ids[1],
                'share_server_id': share_server_id,
                'ip_address': '2.2.2.2',
            },
        ]
        na_table = utils.load_table(self.na_table_name, engine)
        engine.execute(na_table.insert(network_allocations))

    def check_upgrade(self, engine, data):
        na_table = utils.load_table(self.na_table_name, engine)
        for na in engine.execute(na_table.select()):
            self.test_case.assertTrue(hasattr(na, 'gateway'))

        # Create network allocation
        network_allocations = [
            {
                'id': self.na_ids[2],
                'share_server_id': na.share_server_id,
                'ip_address': '3.3.3.3',
                'gateway': '3.3.3.1',
                'network_type': 'vlan',
                'segmentation_id': 1005,
                'ip_version': 4,
                'cidr': '240.0.0.0/16',
            },
        ]
        engine.execute(na_table.insert(network_allocations))

        # Select network allocations with gateway info
        for na in engine.execute(
                na_table.select().where(na_table.c.gateway == '3.3.3.1')):
            self.test_case.assertTrue(hasattr(na, 'gateway'))
            self.test_case.assertEqual(network_allocations[0]['gateway'],
                                       getattr(na, 'gateway'))

        sn_table = utils.load_table(self.sn_table_name, engine)
        for sn in engine.execute(sn_table.select()):
            self.test_case.assertTrue(hasattr(sn, 'gateway'))

        # Create share network
        share_networks = [
            {
                'id': self.sn_ids[1],
                'user_id': sn.user_id,
                'project_id': sn.project_id,
                'gateway': '1.1.1.1',
                'name': 'name_foo',
            },
        ]
        engine.execute(sn_table.insert(share_networks))

        # Select share network
        for sn in engine.execute(
                sn_table.select().where(sn_table.c.name == 'name_foo')):
            self.test_case.assertTrue(hasattr(sn, 'gateway'))
            self.test_case.assertEqual(share_networks[0]['gateway'],
                                       getattr(sn, 'gateway'))

    def check_downgrade(self, engine):
        for table_name, ids in ((self.na_table_name, self.na_ids),
                                (self.sn_table_name, self.sn_ids)):
            table = utils.load_table(table_name, engine)
            db_result = engine.execute(table.select())
            self.test_case.assertTrue(db_result.rowcount >= len(ids))
            for record in db_result:
                self.test_case.assertFalse(hasattr(record, 'gateway'))


@map_to_migration('e8ea58723178')
class RemoveHostFromDriverPrivateDataChecks(BaseMigrationChecks):
    table_name = 'drivers_private_data'
    host_column_name = 'host'

    def setup_upgrade_data(self, engine):
        dpd_data = {
            'created_at': datetime.datetime(2016, 7, 14, 22, 31, 22),
            'deleted': 0,
            'host': 'host1',
            'entity_uuid': 'entity_uuid1',
            'key': 'key1',
            'value': 'value1'
        }
        dpd_table = utils.load_table(self.table_name, engine)
        engine.execute(dpd_table.insert(dpd_data))

    def check_upgrade(self, engine, data):
        dpd_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(dpd_table.select())
        for row in rows:
            self.test_case.assertFalse(hasattr(row, self.host_column_name))

    def check_downgrade(self, engine):
        dpd_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(dpd_table.select())
        for row in rows:
            self.test_case.assertTrue(hasattr(row, self.host_column_name))
            self.test_case.assertEqual('unknown', row[self.host_column_name])


@map_to_migration('493eaffd79e1')
class NewMTUColumnChecks(BaseMigrationChecks):
    na_table_name = 'network_allocations'
    sn_table_name = 'share_networks'
    na_ids = ['network_allocation_id_fake_3_%d' % i for i in (1, 2, 3)]
    sn_ids = ['share_network_id_fake_3_%d' % i for i in (1, 2)]

    def setup_upgrade_data(self, engine):
        user_id = 'user_id'
        project_id = 'project_id'
        share_server_id = 'share_server_id_foo_2'

        # Create share network
        share_network_data = {
            'id': self.sn_ids[0],
            'user_id': user_id,
            'project_id': project_id,
        }
        sn_table = utils.load_table(self.sn_table_name, engine)
        engine.execute(sn_table.insert(share_network_data))

        # Create share server
        share_server_data = {
            'id': share_server_id,
            'share_network_id': share_network_data['id'],
            'host': 'fake_host',
            'status': 'active',
        }
        ss_table = utils.load_table('share_servers', engine)
        engine.execute(ss_table.insert(share_server_data))

        # Create network allocations
        network_allocations = [
            {
                'id': self.na_ids[0],
                'share_server_id': share_server_id,
                'ip_address': '1.1.1.1',
            },
            {
                'id': self.na_ids[1],
                'share_server_id': share_server_id,
                'ip_address': '2.2.2.2',
            },
        ]
        na_table = utils.load_table(self.na_table_name, engine)
        engine.execute(na_table.insert(network_allocations))

    def check_upgrade(self, engine, data):
        na_table = utils.load_table(self.na_table_name, engine)
        for na in engine.execute(na_table.select()):
            self.test_case.assertTrue(hasattr(na, 'mtu'))

        # Create network allocation
        network_allocations = [
            {
                'id': self.na_ids[2],
                'share_server_id': na.share_server_id,
                'ip_address': '3.3.3.3',
                'gateway': '3.3.3.1',
                'network_type': 'vlan',
                'segmentation_id': 1005,
                'ip_version': 4,
                'cidr': '240.0.0.0/16',
                'mtu': 1509,
            },
        ]
        engine.execute(na_table.insert(network_allocations))

        # Select network allocations with mtu info
        for na in engine.execute(
                na_table.select().where(na_table.c.mtu == '1509')):
            self.test_case.assertTrue(hasattr(na, 'mtu'))
            self.test_case.assertEqual(network_allocations[0]['mtu'],
                                       getattr(na, 'mtu'))

        # Select all entries and check for the value
        for na in engine.execute(na_table.select()):
            self.test_case.assertTrue(hasattr(na, 'mtu'))
            if na['id'] == self.na_ids[2]:
                self.test_case.assertEqual(network_allocations[0]['mtu'],
                                           getattr(na, 'mtu'))
            else:
                self.test_case.assertIsNone(na['mtu'])

        sn_table = utils.load_table(self.sn_table_name, engine)
        for sn in engine.execute(sn_table.select()):
            self.test_case.assertTrue(hasattr(sn, 'mtu'))

        # Create share network
        share_networks = [
            {
                'id': self.sn_ids[1],
                'user_id': sn.user_id,
                'project_id': sn.project_id,
                'gateway': '1.1.1.1',
                'name': 'name_foo_2',
                'mtu': 1509,
            },
        ]
        engine.execute(sn_table.insert(share_networks))

        # Select share network with MTU set
        for sn in engine.execute(
                sn_table.select().where(sn_table.c.name == 'name_foo_2')):
            self.test_case.assertTrue(hasattr(sn, 'mtu'))
            self.test_case.assertEqual(share_networks[0]['mtu'],
                                       getattr(sn, 'mtu'))

        # Select all entries and check for the value
        for sn in engine.execute(sn_table.select()):
            self.test_case.assertTrue(hasattr(sn, 'mtu'))
            if sn['id'] == self.sn_ids[1]:
                self.test_case.assertEqual(network_allocations[0]['mtu'],
                                           getattr(sn, 'mtu'))
            else:
                self.test_case.assertIsNone(sn['mtu'])

    def check_downgrade(self, engine):
        for table_name, ids in ((self.na_table_name, self.na_ids),
                                (self.sn_table_name, self.sn_ids)):
            table = utils.load_table(table_name, engine)
            db_result = engine.execute(table.select())
            self.test_case.assertTrue(db_result.rowcount >= len(ids))
            for record in db_result:
                self.test_case.assertFalse(hasattr(record, 'mtu'))


@map_to_migration('63809d875e32')
class AddAccessKeyToShareAccessMapping(BaseMigrationChecks):
    table_name = 'share_access_map'
    access_key_column_name = 'access_key'

    def setup_upgrade_data(self, engine):
        share_data = {
            'id': uuidutils.generate_uuid(),
            'share_proto': "CEPHFS",
            'size': 1,
            'snapshot_id': None,
            'user_id': 'fake',
            'project_id': 'fake'
        }
        share_table = utils.load_table('shares', engine)
        engine.execute(share_table.insert(share_data))

        share_instance_data = {
            'id': uuidutils.generate_uuid(),
            'deleted': 'False',
            'host': 'fake',
            'share_id': share_data['id'],
            'status': 'available',
            'access_rules_status': 'active'
        }
        share_instance_table = utils.load_table('share_instances', engine)
        engine.execute(share_instance_table.insert(share_instance_data))

        share_access_data = {
            'id': uuidutils.generate_uuid(),
            'share_id': share_data['id'],
            'access_type': 'cephx',
            'access_to': 'alice',
            'deleted': 'False'
        }
        share_access_table = utils.load_table(self.table_name, engine)
        engine.execute(share_access_table.insert(share_access_data))

        share_instance_access_data = {
            'id': uuidutils.generate_uuid(),
            'share_instance_id': share_instance_data['id'],
            'access_id': share_access_data['id'],
            'deleted': 'False'
        }
        share_instance_access_table = utils.load_table(
            'share_instance_access_map', engine)
        engine.execute(share_instance_access_table.insert(
            share_instance_access_data))

    def check_upgrade(self, engine, data):
        share_access_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(share_access_table.select())
        for row in rows:
            self.test_case.assertTrue(hasattr(row,
                                              self.access_key_column_name))

    def check_downgrade(self, engine):
        share_access_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(share_access_table.select())
        for row in rows:
            self.test_case.assertFalse(hasattr(row,
                                               self.access_key_column_name))


@map_to_migration('48a7beae3117')
class MoveShareTypeIdToInstancesCheck(BaseMigrationChecks):

    some_shares = [
        {
            'id': 's1',
            'share_type_id': 't1',
        },
        {
            'id': 's2',
            'share_type_id': 't2',
        },
        {
            'id': 's3',
            'share_type_id': 't3',
        },
    ]

    share_ids = [x['id'] for x in some_shares]

    some_instances = [
        {
            'id': 'i1',
            'share_id': 's3',
        },
        {
            'id': 'i2',
            'share_id': 's2',
        },
        {
            'id': 'i3',
            'share_id': 's2',
        },
        {
            'id': 'i4',
            'share_id': 's1',
        },
    ]

    instance_ids = [x['id'] for x in some_instances]

    some_share_types = [
        {'id': 't1'},
        {'id': 't2'},
        {'id': 't3'},
    ]

    def setup_upgrade_data(self, engine):

        shares_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)
        share_types_table = utils.load_table('share_types', engine)

        for stype in self.some_share_types:
            engine.execute(share_types_table.insert(stype))

        for share in self.some_shares:
            engine.execute(shares_table.insert(share))

        for instance in self.some_instances:
            engine.execute(share_instances_table.insert(instance))

    def check_upgrade(self, engine, data):

        shares_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)

        for instance in engine.execute(share_instances_table.select().where(
                share_instances_table.c.id in self.instance_ids)):
            share = engine.execute(shares_table.select().where(
                instance['share_id'] == shares_table.c.id)).first()
            self.test_case.assertEqual(
                next((x for x in self.some_shares if share['id'] == x['id']),
                     None)['share_type_id'],
                instance['share_type_id'])

        for share in engine.execute(share_instances_table.select().where(
                shares_table.c.id in self.share_ids)):
            self.test_case.assertNotIn('share_type_id', share)

    def check_downgrade(self, engine):

        shares_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)

        for instance in engine.execute(share_instances_table.select().where(
                share_instances_table.c.id in self.instance_ids)):
            self.test_case.assertNotIn('share_type_id', instance)

        for share in engine.execute(share_instances_table.select().where(
                shares_table.c.id in self.share_ids)):
            self.test_case.assertEqual(
                next((x for x in self.some_shares if share['id'] == x['id']),
                     None)['share_type_id'],
                share['share_type_id'])


@map_to_migration('3e7d62517afa')
class CreateFromSnapshotExtraSpecAndShareColumn(BaseMigrationChecks):

    expected_attr = constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT
    snap_support_attr = constants.ExtraSpecs.SNAPSHOT_SUPPORT

    def _get_fake_data(self):
        extra_specs = []
        shares = []
        share_instances = []
        share_types = [
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'share-type-1',
                'is_public': False,
            },
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'share-type-2',
                'is_public': True,
            },
        ]
        snapshot_support = (False, True)
        dhss = ('True', 'False')
        for idx, share_type in enumerate(share_types):
            extra_specs.append({
                'share_type_id': share_type['id'],
                'spec_key': 'snapshot_support',
                'spec_value': snapshot_support[idx],
                'deleted': 0,
            })
            extra_specs.append({
                'share_type_id': share_type['id'],
                'spec_key': 'driver_handles_share_servers',
                'spec_value': dhss[idx],
                'deleted': 0,
            })
            share = fake_share(snapshot_support=snapshot_support[idx])
            shares.append(share)
            share_instances.append(
                fake_instance(share_id=share['id'],
                              share_type_id=share_type['id'])
            )

        return share_types, extra_specs, shares, share_instances

    def setup_upgrade_data(self, engine):

        (self.share_types, self.extra_specs, self.shares,
         self.share_instances) = self._get_fake_data()

        share_types_table = utils.load_table('share_types', engine)
        engine.execute(share_types_table.insert(self.share_types))
        extra_specs_table = utils.load_table('share_type_extra_specs',
                                             engine)
        engine.execute(extra_specs_table.insert(self.extra_specs))
        shares_table = utils.load_table('shares', engine)
        engine.execute(shares_table.insert(self.shares))
        share_instances_table = utils.load_table('share_instances', engine)
        engine.execute(share_instances_table.insert(self.share_instances))

    def check_upgrade(self, engine, data):
        share_type_ids = [st['id'] for st in self.share_types]
        share_ids = [s['id'] for s in self.shares]
        shares_table = utils.load_table('shares', engine)
        share_types_table = utils.load_table('share_types', engine)
        extra_specs_table = utils.load_table('share_type_extra_specs',
                                             engine)

        # Pre-existing Shares must be present
        shares_in_db = engine.execute(shares_table.select()).fetchall()
        share_ids_in_db = [s['id'] for s in shares_in_db]
        self.test_case.assertTrue(len(share_ids_in_db) > 1)
        for share_id in share_ids:
            self.test_case.assertIn(share_id, share_ids_in_db)

        # new shares attr must match snapshot support
        for share in shares_in_db:
            self.test_case.assertTrue(hasattr(share, self.expected_attr))
            self.test_case.assertEqual(share[self.snap_support_attr],
                                       share[self.expected_attr])

        # Pre-existing Share types must be present
        share_types_in_db = (
            engine.execute(share_types_table.select()).fetchall())
        share_type_ids_in_db = [s['id'] for s in share_types_in_db]
        for share_type_id in share_type_ids:
            self.test_case.assertIn(share_type_id, share_type_ids_in_db)

        # Pre-existing extra specs must be present
        extra_specs_in_db = (
            engine.execute(extra_specs_table.select().where(
                extra_specs_table.c.deleted == 0)).fetchall())
        self.test_case.assertGreaterEqual(len(extra_specs_in_db),
                                          len(self.extra_specs))

        # New Extra spec for share types must match snapshot support
        for share_type_id in share_type_ids:
            new_extra_spec = [x for x in extra_specs_in_db
                              if x['spec_key'] == self.expected_attr
                              and x['share_type_id'] == share_type_id]
            snapshot_support_spec = [
                x for x in extra_specs_in_db
                if x['spec_key'] == self.snap_support_attr
                and x['share_type_id'] == share_type_id]
            self.test_case.assertEqual(1, len(new_extra_spec))
            self.test_case.assertEqual(1, len(snapshot_support_spec))
            self.test_case.assertEqual(
                snapshot_support_spec[0]['spec_value'],
                new_extra_spec[0]['spec_value'])

    def check_downgrade(self, engine):
        share_type_ids = [st['id'] for st in self.share_types]
        share_ids = [s['id'] for s in self.shares]
        shares_table = utils.load_table('shares', engine)
        share_types_table = utils.load_table('share_types', engine)
        extra_specs_table = utils.load_table('share_type_extra_specs',
                                             engine)

        # Pre-existing Shares must be present
        shares_in_db = engine.execute(shares_table.select()).fetchall()
        share_ids_in_db = [s['id'] for s in shares_in_db]
        self.test_case.assertTrue(len(share_ids_in_db) > 1)
        for share_id in share_ids:
            self.test_case.assertIn(share_id, share_ids_in_db)

        # Shares should have no attr to create share from snapshot
        for share in shares_in_db:
            self.test_case.assertFalse(hasattr(share, self.expected_attr))

        # Pre-existing Share types must be present
        share_types_in_db = (
            engine.execute(share_types_table.select()).fetchall())
        share_type_ids_in_db = [s['id'] for s in share_types_in_db]
        for share_type_id in share_type_ids:
            self.test_case.assertIn(share_type_id, share_type_ids_in_db)

        # Pre-existing extra specs must be present
        extra_specs_in_db = (
            engine.execute(extra_specs_table.select().where(
                extra_specs_table.c.deleted == 0)).fetchall())
        self.test_case.assertGreaterEqual(len(extra_specs_in_db),
                                          len(self.extra_specs))

        # Share types must not have create share from snapshot extra spec
        for share_type_id in share_type_ids:
            new_extra_spec = [x for x in extra_specs_in_db
                              if x['spec_key'] == self.expected_attr
                              and x['share_type_id'] == share_type_id]
            self.test_case.assertEqual(0, len(new_extra_spec))


@map_to_migration('87ce15c59bbe')
class RevertToSnapshotShareColumn(BaseMigrationChecks):

    expected_attr = constants.ExtraSpecs.REVERT_TO_SNAPSHOT_SUPPORT

    def _get_fake_data(self):
        extra_specs = []
        shares = []
        share_instances = []
        share_types = [
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'revert-1',
                'is_public': False,
            },
            {
                'id': uuidutils.generate_uuid(),
                'deleted': 'False',
                'name': 'revert-2',
                'is_public': True,

            },
        ]
        snapshot_support = (False, True)
        dhss = ('True', 'False')
        for idx, share_type in enumerate(share_types):
            extra_specs.append({
                'share_type_id': share_type['id'],
                'spec_key': 'snapshot_support',
                'spec_value': snapshot_support[idx],
                'deleted': 0,
            })
            extra_specs.append({
                'share_type_id': share_type['id'],
                'spec_key': 'driver_handles_share_servers',
                'spec_value': dhss[idx],
                'deleted': 0,
            })
            share = fake_share(snapshot_support=snapshot_support[idx])
            shares.append(share)
            share_instances.append(
                fake_instance(share_id=share['id'],
                              share_type_id=share_type['id'])
            )

        return share_types, extra_specs, shares, share_instances

    def setup_upgrade_data(self, engine):

        (self.share_types, self.extra_specs, self.shares,
            self.share_instances) = self._get_fake_data()

        share_types_table = utils.load_table('share_types', engine)
        engine.execute(share_types_table.insert(self.share_types))
        extra_specs_table = utils.load_table('share_type_extra_specs',
                                             engine)
        engine.execute(extra_specs_table.insert(self.extra_specs))
        shares_table = utils.load_table('shares', engine)
        engine.execute(shares_table.insert(self.shares))
        share_instances_table = utils.load_table('share_instances', engine)
        engine.execute(share_instances_table.insert(self.share_instances))

    def check_upgrade(self, engine, data):
        share_ids = [s['id'] for s in self.shares]
        shares_table = utils.load_table('shares', engine)

        # Pre-existing Shares must be present
        shares_in_db = engine.execute(shares_table.select().where(
            shares_table.c.deleted == 'False')).fetchall()
        share_ids_in_db = [s['id'] for s in shares_in_db]
        self.test_case.assertTrue(len(share_ids_in_db) > 1)
        for share_id in share_ids:
            self.test_case.assertIn(share_id, share_ids_in_db)

        # New shares attr must be present and set to False
        for share in shares_in_db:
            self.test_case.assertTrue(hasattr(share, self.expected_attr))
            self.test_case.assertEqual(False, share[self.expected_attr])

    def check_downgrade(self, engine):
        share_ids = [s['id'] for s in self.shares]
        shares_table = utils.load_table('shares', engine)

        # Pre-existing Shares must be present
        shares_in_db = engine.execute(shares_table.select()).fetchall()
        share_ids_in_db = [s['id'] for s in shares_in_db]
        self.test_case.assertTrue(len(share_ids_in_db) > 1)
        for share_id in share_ids:
            self.test_case.assertIn(share_id, share_ids_in_db)

        # Shares should have no attr to revert share to snapshot
        for share in shares_in_db:
            self.test_case.assertFalse(hasattr(share, self.expected_attr))


@map_to_migration('95e3cf760840')
class RemoveNovaNetIdColumnFromShareNetworks(BaseMigrationChecks):
    table_name = 'share_networks'
    nova_net_column_name = 'nova_net_id'

    def setup_upgrade_data(self, engine):
        user_id = 'user_id'
        project_id = 'project_id'
        nova_net_id = 'foo_nova_net_id'

        share_network_data = {
            'id': 'foo_share_network_id_3',
            'user_id': user_id,
            'project_id': project_id,
            'nova_net_id': nova_net_id,
        }
        sn_table = utils.load_table(self.table_name, engine)
        engine.execute(sn_table.insert(share_network_data))

    def check_upgrade(self, engine, data):
        sn_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(sn_table.select())
        self.test_case.assertGreater(rows.rowcount, 0)
        for row in rows:
            self.test_case.assertFalse(hasattr(row, self.nova_net_column_name))

    def check_downgrade(self, engine):
        sn_table = utils.load_table(self.table_name, engine)
        rows = engine.execute(sn_table.select())
        self.test_case.assertGreater(rows.rowcount, 0)
        for row in rows:
            self.test_case.assertTrue(hasattr(row, self.nova_net_column_name))
            self.test_case.assertIsNone(row[self.nova_net_column_name])


@map_to_migration('54667b9cade7')
class RestoreStateToShareInstanceAccessMap(BaseMigrationChecks):
    new_instance_mapping_state = {
        constants.STATUS_ACTIVE: constants.STATUS_ACTIVE,
        constants.SHARE_INSTANCE_RULES_SYNCING:
            constants.ACCESS_STATE_QUEUED_TO_APPLY,
        constants.STATUS_OUT_OF_SYNC: constants.ACCESS_STATE_QUEUED_TO_APPLY,
        'updating': constants.ACCESS_STATE_QUEUED_TO_APPLY,
        'updating_multiple': constants.ACCESS_STATE_QUEUED_TO_APPLY,
        constants.SHARE_INSTANCE_RULES_ERROR: constants.ACCESS_STATE_ERROR,
    }

    new_access_rules_status = {
        constants.STATUS_ACTIVE: constants.STATUS_ACTIVE,
        constants.STATUS_OUT_OF_SYNC: constants.SHARE_INSTANCE_RULES_SYNCING,
        'updating': constants.SHARE_INSTANCE_RULES_SYNCING,
        'updating_multiple': constants.SHARE_INSTANCE_RULES_SYNCING,
        constants.SHARE_INSTANCE_RULES_ERROR:
            constants.SHARE_INSTANCE_RULES_ERROR,
    }

    @staticmethod
    def generate_share_instance(sid, access_rules_status):
        share_instance_data = {
            'id': uuidutils.generate_uuid(),
            'deleted': 'False',
            'host': 'fake',
            'share_id': sid,
            'status': constants.STATUS_AVAILABLE,
            'access_rules_status': access_rules_status
        }
        return share_instance_data

    @staticmethod
    def generate_share_instance_access_map(share_access_data_id,
                                           share_instance_id):
        share_instance_access_data = {
            'id': uuidutils.generate_uuid(),
            'share_instance_id': share_instance_id,
            'access_id': share_access_data_id,
            'deleted': 'False'
        }
        return share_instance_access_data

    def setup_upgrade_data(self, engine):
        share_data = {
            'id': uuidutils.generate_uuid(),
            'share_proto': 'fake',
            'size': 1,
            'snapshot_id': None,
            'user_id': 'fake',
            'project_id': 'fake'
        }
        share_table = utils.load_table('shares', engine)
        engine.execute(share_table.insert(share_data))

        share_instances = [
            self.generate_share_instance(
                share_data['id'], constants.STATUS_ACTIVE),
            self.generate_share_instance(
                share_data['id'], constants.STATUS_OUT_OF_SYNC),
            self.generate_share_instance(
                share_data['id'], constants.STATUS_ERROR),
            self.generate_share_instance(
                share_data['id'], 'updating'),
            self.generate_share_instance(
                share_data['id'], 'updating_multiple'),
        ]
        self.updating_share_instance = share_instances[3]
        self.updating_multiple_share_instance = share_instances[4]

        share_instance_table = utils.load_table('share_instances', engine)
        for share_instance_data in share_instances:
            engine.execute(share_instance_table.insert(share_instance_data))

        share_access_data = {
            'id': uuidutils.generate_uuid(),
            'share_id': share_data['id'],
            'access_type': 'fake',
            'access_to': 'alice',
            'deleted': 'False'
        }
        share_access_table = utils.load_table('share_access_map', engine)
        engine.execute(share_access_table.insert(share_access_data))

        share_instance_access_data = []
        for share_instance in share_instances:
            sia_map = self.generate_share_instance_access_map(
                share_access_data['id'], share_instance['id'])
            share_instance_access_data.append(sia_map)

        share_instance_access_table = utils.load_table(
            'share_instance_access_map', engine)
        for sia_map in share_instance_access_data:
            engine.execute(share_instance_access_table.insert(sia_map))

    def check_upgrade(self, engine, data):
        share_instance_table = utils.load_table('share_instances', engine)
        sia_table = utils.load_table('share_instance_access_map', engine)

        for rule in engine.execute(sia_table.select()):
            self.test_case.assertTrue(hasattr(rule, 'state'))
            correlated_share_instances = engine.execute(
                share_instance_table.select().where(
                    share_instance_table.c.id == rule['share_instance_id']))
            access_rules_status = getattr(correlated_share_instances.first(),
                                          'access_rules_status')
            self.test_case.assertEqual(
                self.new_instance_mapping_state[access_rules_status],
                rule['state'])

        for instance in engine.execute(share_instance_table.select()):
            self.test_case.assertTrue(instance['access_rules_status']
                                      not in ('updating',
                                              'updating_multiple',
                                              constants.STATUS_OUT_OF_SYNC))
            if instance['id'] in (self.updating_share_instance['id'],
                                  self.updating_multiple_share_instance['id']):
                self.test_case.assertEqual(
                    constants.SHARE_INSTANCE_RULES_SYNCING,
                    instance['access_rules_status'])

    def check_downgrade(self, engine):
        share_instance_table = utils.load_table('share_instances', engine)
        sia_table = utils.load_table('share_instance_access_map', engine)
        for rule in engine.execute(sia_table.select()):
            self.test_case.assertFalse(hasattr(rule, 'state'))

        for instance in engine.execute(share_instance_table.select()):
            if instance['id'] in (self.updating_share_instance['id'],
                                  self.updating_multiple_share_instance['id']):
                self.test_case.assertEqual(
                    constants.STATUS_OUT_OF_SYNC,
                    instance['access_rules_status'])


@map_to_migration('e9f79621d83f')
class AddCastRulesToReadonlyToInstances(BaseMigrationChecks):

    share_type = {
        'id': uuidutils.generate_uuid(),
    }

    shares = [
        {
            'id': uuidutils.generate_uuid(),
            'replication_type': constants.REPLICATION_TYPE_READABLE,
        },
        {
            'id': uuidutils.generate_uuid(),
            'replication_type': constants.REPLICATION_TYPE_READABLE,
        },
        {
            'id': uuidutils.generate_uuid(),
            'replication_type': constants.REPLICATION_TYPE_WRITABLE,
        },
        {
            'id': uuidutils.generate_uuid(),
        },
    ]
    share_ids = [x['id'] for x in shares]

    correct_instance = {
        'id': uuidutils.generate_uuid(),
        'share_id': share_ids[1],
        'replica_state': constants.REPLICA_STATE_IN_SYNC,
        'status': constants.STATUS_AVAILABLE,
        'share_type_id': share_type['id'],
    }

    instances = [
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[0],
            'replica_state': constants.REPLICA_STATE_ACTIVE,
            'status': constants.STATUS_AVAILABLE,
            'share_type_id': share_type['id'],
        },
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[0],
            'replica_state': constants.REPLICA_STATE_IN_SYNC,
            'status': constants.STATUS_REPLICATION_CHANGE,
            'share_type_id': share_type['id'],
        },
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[1],
            'replica_state': constants.REPLICA_STATE_ACTIVE,
            'status': constants.STATUS_REPLICATION_CHANGE,
            'share_type_id': share_type['id'],
        },
        correct_instance,
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[2],
            'replica_state': constants.REPLICA_STATE_ACTIVE,
            'status': constants.STATUS_REPLICATION_CHANGE,
            'share_type_id': share_type['id'],
        },
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[2],
            'replica_state': constants.REPLICA_STATE_IN_SYNC,
            'status': constants.STATUS_AVAILABLE,
            'share_type_id': share_type['id'],
        },
        {
            'id': uuidutils.generate_uuid(),
            'share_id': share_ids[3],
            'status': constants.STATUS_AVAILABLE,
            'share_type_id': share_type['id'],
        },
    ]
    instance_ids = share_ids = [x['id'] for x in instances]

    def setup_upgrade_data(self, engine):
        shares_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)
        share_types_table = utils.load_table('share_types', engine)

        engine.execute(share_types_table.insert(self.share_type))

        for share in self.shares:
            engine.execute(shares_table.insert(share))

        for instance in self.instances:
            engine.execute(share_instances_table.insert(instance))

    def check_upgrade(self, engine, data):

        shares_table = utils.load_table('shares', engine)
        share_instances_table = utils.load_table('share_instances', engine)

        for instance in engine.execute(share_instances_table.select().where(
                share_instances_table.c.id in self.instance_ids)):
            self.test_case.assertIn('cast_rules_to_readonly', instance)
            share = engine.execute(shares_table.select().where(
                instance['share_id'] == shares_table.c.id)).first()
            if (instance['replica_state'] != constants.REPLICA_STATE_ACTIVE and
                    share['replication_type'] ==
                    constants.REPLICATION_TYPE_READABLE and
                    instance['status'] != constants.STATUS_REPLICATION_CHANGE):
                self.test_case.assertTrue(instance['cast_rules_to_readonly'])
                self.test_case.assertEqual(instance['id'],
                                           self.correct_instance['id'])
            else:
                self.test_case.assertEqual(
                    False, instance['cast_rules_to_readonly'])

    def check_downgrade(self, engine):

        share_instances_table = utils.load_table('share_instances', engine)

        for instance in engine.execute(share_instances_table.select()):
            self.test_case.assertNotIn('cast_rules_to_readonly', instance)


@map_to_migration('03da71c0e321')
class ShareGroupMigrationChecks(BaseMigrationChecks):

    def setup_upgrade_data(self, engine):
        # Create share type
        self.share_type_id = uuidutils.generate_uuid()
        st_fixture = {
            'deleted': "False",
            'id': self.share_type_id,
        }
        st_table = utils.load_table('share_types', engine)
        engine.execute(st_table.insert(st_fixture))

        # Create CG
        self.cg_id = uuidutils.generate_uuid()
        cg_fixture = {
            'deleted': "False",
            'id': self.cg_id,
            'user_id': 'fake_user',
            'project_id': 'fake_project_id',
        }
        cg_table = utils.load_table('consistency_groups', engine)
        engine.execute(cg_table.insert(cg_fixture))

        # Create share_type group mapping
        self.mapping_id = uuidutils.generate_uuid()
        mapping_fixture = {
            'deleted': "False",
            'id': self.mapping_id,
            'consistency_group_id': self.cg_id,
            'share_type_id': self.share_type_id,
        }
        mapping_table = utils.load_table(
            'consistency_group_share_type_mappings', engine)
        engine.execute(mapping_table.insert(mapping_fixture))

        # Create share
        self.share_id = uuidutils.generate_uuid()
        share_fixture = {
            'deleted': "False",
            'id': self.share_id,
            'consistency_group_id': self.cg_id,
            'user_id': 'fake_user',
            'project_id': 'fake_project_id',
        }
        share_table = utils.load_table('shares', engine)
        engine.execute(share_table.insert(share_fixture))

        # Create share instance
        self.share_instance_id = uuidutils.generate_uuid()
        share_instance_fixture = {
            'deleted': "False",
            'share_type_id': self.share_type_id,
            'id': self.share_instance_id,
            'share_id': self.share_id,
            'cast_rules_to_readonly': False,
        }
        share_instance_table = utils.load_table('share_instances', engine)
        engine.execute(share_instance_table.insert(share_instance_fixture))

        # Create cgsnapshot
        self.cgsnapshot_id = uuidutils.generate_uuid()
        cg_snap_fixture = {
            'deleted': "False",
            'id': self.cgsnapshot_id,
            'consistency_group_id': self.cg_id,
            'user_id': 'fake_user',
            'project_id': 'fake_project_id',
        }
        cgsnapshots_table = utils.load_table('cgsnapshots', engine)
        engine.execute(cgsnapshots_table.insert(cg_snap_fixture))

        # Create cgsnapshot member
        self.cgsnapshot_member_id = uuidutils.generate_uuid()
        cg_snap_member_fixture = {
            'deleted': "False",
            'id': self.cgsnapshot_member_id,
            'cgsnapshot_id': self.cgsnapshot_id,
            'share_type_id': self.share_type_id,
            'share_instance_id': self.share_instance_id,
            'share_id': self.share_id,
            'user_id': 'fake_user',
            'project_id': 'fake_project_id',
        }
        cgsnapshot_members_table = utils.load_table(
            'cgsnapshot_members', engine)
        engine.execute(cgsnapshot_members_table.insert(cg_snap_member_fixture))

    def check_upgrade(self, engine, data):
        sg_table = utils.load_table("share_groups", engine)
        db_result = engine.execute(sg_table.select().where(
            sg_table.c.id == self.cg_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        sg = db_result.first()
        self.test_case.assertIsNone(sg['source_share_group_snapshot_id'])

        share_table = utils.load_table("shares", engine)
        share_result = engine.execute(share_table.select().where(
            share_table.c.id == self.share_id))
        self.test_case.assertEqual(1, share_result.rowcount)
        share = share_result.first()
        self.test_case.assertEqual(self.cg_id, share['share_group_id'])
        self.test_case.assertIsNone(
            share['source_share_group_snapshot_member_id'])

        mapping_table = utils.load_table(
            "share_group_share_type_mappings", engine)
        mapping_result = engine.execute(mapping_table.select().where(
            mapping_table.c.id == self.mapping_id))
        self.test_case.assertEqual(1, mapping_result.rowcount)
        mapping_record = mapping_result.first()
        self.test_case.assertEqual(
            self.cg_id, mapping_record['share_group_id'])
        self.test_case.assertEqual(
            self.share_type_id, mapping_record['share_type_id'])

        sgs_table = utils.load_table("share_group_snapshots", engine)
        db_result = engine.execute(sgs_table.select().where(
            sgs_table.c.id == self.cgsnapshot_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        sgs = db_result.first()
        self.test_case.assertEqual(self.cg_id, sgs['share_group_id'])

        sgsm_table = utils.load_table("share_group_snapshot_members", engine)
        db_result = engine.execute(sgsm_table.select().where(
            sgsm_table.c.id == self.cgsnapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        sgsm = db_result.first()
        self.test_case.assertEqual(
            self.cgsnapshot_id, sgsm['share_group_snapshot_id'])
        self.test_case.assertNotIn('share_type_id', sgsm)

    def check_downgrade(self, engine):
        cg_table = utils.load_table("consistency_groups", engine)
        db_result = engine.execute(cg_table.select().where(
            cg_table.c.id == self.cg_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        cg = db_result.first()
        self.test_case.assertIsNone(cg['source_cgsnapshot_id'])

        share_table = utils.load_table("shares", engine)
        share_result = engine.execute(share_table.select().where(
            share_table.c.id == self.share_id))
        self.test_case.assertEqual(1, share_result.rowcount)
        share = share_result.first()
        self.test_case.assertEqual(self.cg_id, share['consistency_group_id'])
        self.test_case.assertIsNone(
            share['source_cgsnapshot_member_id'])

        mapping_table = utils.load_table(
            "consistency_group_share_type_mappings", engine)
        mapping_result = engine.execute(mapping_table.select().where(
            mapping_table.c.id == self.mapping_id))
        self.test_case.assertEqual(1, mapping_result.rowcount)
        cg_st_mapping = mapping_result.first()
        self.test_case.assertEqual(
            self.cg_id, cg_st_mapping['consistency_group_id'])
        self.test_case.assertEqual(
            self.share_type_id, cg_st_mapping['share_type_id'])

        cg_snapshots_table = utils.load_table("cgsnapshots", engine)
        db_result = engine.execute(cg_snapshots_table.select().where(
            cg_snapshots_table.c.id == self.cgsnapshot_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        cgsnap = db_result.first()
        self.test_case.assertEqual(self.cg_id, cgsnap['consistency_group_id'])

        cg_snap_member_table = utils.load_table("cgsnapshot_members", engine)
        db_result = engine.execute(cg_snap_member_table.select().where(
            cg_snap_member_table.c.id == self.cgsnapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        member = db_result.first()
        self.test_case.assertEqual(
            self.cgsnapshot_id, member['cgsnapshot_id'])
        self.test_case.assertIn('share_type_id', member)
        self.test_case.assertEqual(self.share_type_id, member['share_type_id'])


@map_to_migration('927920b37453')
class ShareGroupSnapshotMemberNewProviderLocationColumnChecks(
        BaseMigrationChecks):
    table_name = 'share_group_snapshot_members'
    share_group_type_id = uuidutils.generate_uuid()
    share_group_id = uuidutils.generate_uuid()
    share_id = uuidutils.generate_uuid()
    share_instance_id = uuidutils.generate_uuid()
    share_group_snapshot_id = uuidutils.generate_uuid()
    share_group_snapshot_member_id = uuidutils.generate_uuid()

    def setup_upgrade_data(self, engine):
        # Setup share group type
        sgt_data = {
            'id': self.share_group_type_id,
            'name': uuidutils.generate_uuid(),
        }
        sgt_table = utils.load_table('share_group_types', engine)
        engine.execute(sgt_table.insert(sgt_data))

        # Setup share group
        sg_data = {
            'id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
            'share_group_type_id': self.share_group_type_id,
        }
        sg_table = utils.load_table('share_groups', engine)
        engine.execute(sg_table.insert(sg_data))

        # Setup shares
        share_data = {
            'id': self.share_id,
            'share_group_id': self.share_group_id,
        }
        s_table = utils.load_table('shares', engine)
        engine.execute(s_table.insert(share_data))

        # Setup share instances
        share_instance_data = {
            'id': self.share_instance_id,
            'share_id': share_data['id'],
            'cast_rules_to_readonly': False,
        }
        si_table = utils.load_table('share_instances', engine)
        engine.execute(si_table.insert(share_instance_data))

        # Setup share group snapshot
        sgs_data = {
            'id': self.share_group_snapshot_id,
            'share_group_id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
        }
        sgs_table = utils.load_table('share_group_snapshots', engine)
        engine.execute(sgs_table.insert(sgs_data))

        # Setup share group snapshot member
        sgsm_data = {
            'id': self.share_group_snapshot_member_id,
            'share_group_snapshot_id': self.share_group_snapshot_id,
            'share_id': self.share_id,
            'share_instance_id': self.share_instance_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
        }
        sgsm_table = utils.load_table(self.table_name, engine)
        engine.execute(sgsm_table.insert(sgsm_data))

    def check_upgrade(self, engine, data):
        sgsm_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sgsm_table.select().where(
            sgsm_table.c.id == self.share_group_snapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sgsm in db_result:
            self.test_case.assertTrue(hasattr(sgsm, 'provider_location'))

            # Check that we can write string data to the new field
            engine.execute(sgsm_table.update().where(
                sgsm_table.c.id == self.share_group_snapshot_member_id,
            ).values({
                'provider_location': ('z' * 255),
            }))

    def check_downgrade(self, engine):
        sgsm_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sgsm_table.select().where(
            sgsm_table.c.id == self.share_group_snapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sgsm in db_result:
            self.test_case.assertFalse(hasattr(sgsm, 'provider_location'))


@map_to_migration('d5db24264f5c')
class ShareGroupNewConsistentSnapshotSupportColumnChecks(BaseMigrationChecks):
    table_name = 'share_groups'
    new_attr_name = 'consistent_snapshot_support'
    share_group_type_id = uuidutils.generate_uuid()
    share_group_id = uuidutils.generate_uuid()

    def setup_upgrade_data(self, engine):
        # Setup share group type
        sgt_data = {
            'id': self.share_group_type_id,
            'name': uuidutils.generate_uuid(),
        }
        sgt_table = utils.load_table('share_group_types', engine)
        engine.execute(sgt_table.insert(sgt_data))

        # Setup share group
        sg_data = {
            'id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
            'share_group_type_id': self.share_group_type_id,
        }
        sg_table = utils.load_table('share_groups', engine)
        engine.execute(sg_table.insert(sg_data))

    def check_upgrade(self, engine, data):
        sg_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sg_table.select().where(
            sg_table.c.id == self.share_group_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sg in db_result:
            self.test_case.assertTrue(hasattr(sg, self.new_attr_name))

            # Check that we can write proper enum data to the new field
            for value in (None, 'pool', 'host'):
                engine.execute(sg_table.update().where(
                    sg_table.c.id == self.share_group_id,
                ).values({self.new_attr_name: value}))

            # Check that we cannot write values that are not allowed by enum.
            for value in ('', 'fake', 'pool1', 'host1', '1pool', '1host'):
                self.test_case.assertRaises(
                    oslo_db_exc.DBError,
                    engine.execute,
                    sg_table.update().where(
                        sg_table.c.id == self.share_group_id
                    ).values({self.new_attr_name: value})
                )

    def check_downgrade(self, engine):
        sg_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sg_table.select().where(
            sg_table.c.id == self.share_group_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sg in db_result:
            self.test_case.assertFalse(hasattr(sg, self.new_attr_name))


@map_to_migration('7d142971c4ef')
class ReservationExpireIndexChecks(BaseMigrationChecks):

    def setup_upgrade_data(self, engine):
        pass

    def _get_reservations_expire_delete_index(self, engine):
        reservation_table = utils.load_table('reservations', engine)
        members = ['deleted', 'expire']
        for idx in reservation_table.indexes:
            if sorted(idx.columns.keys()) == members:
                return idx

    def check_upgrade(self, engine, data):
        self.test_case.assertTrue(
            self._get_reservations_expire_delete_index(engine))

    def check_downgrade(self, engine):
        self.test_case.assertFalse(
            self._get_reservations_expire_delete_index(engine))


@map_to_migration('5237b6625330')
class ShareGroupNewAvailabilityZoneIDColumnChecks(BaseMigrationChecks):
    table_name = 'share_groups'
    new_attr_name = 'availability_zone_id'
    share_group_type_id = uuidutils.generate_uuid()
    share_group_id = uuidutils.generate_uuid()
    availability_zone_id = uuidutils.generate_uuid()

    def setup_upgrade_data(self, engine):
        # Setup AZ
        az_data = {
            'id': self.availability_zone_id,
            'name': uuidutils.generate_uuid(),
        }
        az_table = utils.load_table('availability_zones', engine)
        engine.execute(az_table.insert(az_data))

        # Setup share group type
        sgt_data = {
            'id': self.share_group_type_id,
            'name': uuidutils.generate_uuid(),
        }
        sgt_table = utils.load_table('share_group_types', engine)
        engine.execute(sgt_table.insert(sgt_data))

        # Setup share group
        sg_data = {
            'id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
            'share_group_type_id': self.share_group_type_id,
        }
        sg_table = utils.load_table('share_groups', engine)
        engine.execute(sg_table.insert(sg_data))

    def check_upgrade(self, engine, data):
        sg_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sg_table.select().where(
            sg_table.c.id == self.share_group_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sg in db_result:
            self.test_case.assertTrue(hasattr(sg, self.new_attr_name))

            # Check that we can write proper data to the new field
            for value in (None, self.availability_zone_id):
                engine.execute(sg_table.update().where(
                    sg_table.c.id == self.share_group_id,
                ).values({self.new_attr_name: value}))

    def check_downgrade(self, engine):
        sg_table = utils.load_table(self.table_name, engine)
        db_result = engine.execute(sg_table.select().where(
            sg_table.c.id == self.share_group_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sg in db_result:
            self.test_case.assertFalse(hasattr(sg, self.new_attr_name))


@map_to_migration('31252d671ae5')
class SquashSGSnapshotMembersAndSSIModelsChecks(BaseMigrationChecks):
    old_table_name = 'share_group_snapshot_members'
    new_table_name = 'share_snapshot_instances'
    share_group_type_id = uuidutils.generate_uuid()
    share_group_id = uuidutils.generate_uuid()
    share_id = uuidutils.generate_uuid()
    share_instance_id = uuidutils.generate_uuid()
    share_group_snapshot_id = uuidutils.generate_uuid()
    share_group_snapshot_member_id = uuidutils.generate_uuid()
    keys = (
        'user_id', 'project_id', 'size', 'share_proto',
        'share_group_snapshot_id',
    )

    def setup_upgrade_data(self, engine):
        # Setup share group type
        sgt_data = {
            'id': self.share_group_type_id,
            'name': uuidutils.generate_uuid(),
        }
        sgt_table = utils.load_table('share_group_types', engine)
        engine.execute(sgt_table.insert(sgt_data))

        # Setup share group
        sg_data = {
            'id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
            'share_group_type_id': self.share_group_type_id,
        }
        sg_table = utils.load_table('share_groups', engine)
        engine.execute(sg_table.insert(sg_data))

        # Setup shares
        share_data = {
            'id': self.share_id,
            'share_group_id': self.share_group_id,
        }
        s_table = utils.load_table('shares', engine)
        engine.execute(s_table.insert(share_data))

        # Setup share instances
        share_instance_data = {
            'id': self.share_instance_id,
            'share_id': share_data['id'],
            'cast_rules_to_readonly': False,
        }
        si_table = utils.load_table('share_instances', engine)
        engine.execute(si_table.insert(share_instance_data))

        # Setup share group snapshot
        sgs_data = {
            'id': self.share_group_snapshot_id,
            'share_group_id': self.share_group_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
        }
        sgs_table = utils.load_table('share_group_snapshots', engine)
        engine.execute(sgs_table.insert(sgs_data))

        # Setup share group snapshot member
        sgsm_data = {
            'id': self.share_group_snapshot_member_id,
            'share_group_snapshot_id': self.share_group_snapshot_id,
            'share_id': self.share_id,
            'share_instance_id': self.share_instance_id,
            'project_id': 'fake_project_id',
            'user_id': 'fake_user_id',
        }
        sgsm_table = utils.load_table(self.old_table_name, engine)
        engine.execute(sgsm_table.insert(sgsm_data))

    def check_upgrade(self, engine, data):
        ssi_table = utils.load_table(self.new_table_name, engine)
        db_result = engine.execute(ssi_table.select().where(
            ssi_table.c.id == self.share_group_snapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for ssi in db_result:
            for key in self.keys:
                self.test_case.assertTrue(hasattr(ssi, key))

            # Check that we can write string data to the new fields
            engine.execute(ssi_table.update().where(
                ssi_table.c.id == self.share_group_snapshot_member_id,
            ).values({
                'user_id': ('u' * 255),
                'project_id': ('p' * 255),
                'share_proto': ('s' * 255),
                'size': 123456789,
                'share_group_snapshot_id': self.share_group_snapshot_id,
            }))

        # Check that table 'share_group_snapshot_members' does not
        # exist anymore
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, 'share_group_snapshot_members', engine)

    def check_downgrade(self, engine):
        sgsm_table = utils.load_table(self.old_table_name, engine)
        db_result = engine.execute(sgsm_table.select().where(
            sgsm_table.c.id == self.share_group_snapshot_member_id))
        self.test_case.assertEqual(1, db_result.rowcount)
        for sgsm in db_result:
            for key in self.keys:
                self.test_case.assertTrue(hasattr(sgsm, key))

        # Check that create SGS member is absent in SSI table
        ssi_table = utils.load_table(self.new_table_name, engine)
        db_result = engine.execute(ssi_table.select().where(
            ssi_table.c.id == self.share_group_snapshot_member_id))
        self.test_case.assertEqual(0, db_result.rowcount)


@map_to_migration('238720805ce1')
class MessagesTableChecks(BaseMigrationChecks):
    new_table_name = 'messages'

    def setup_upgrade_data(self, engine):
        pass

    def check_upgrade(self, engine, data):
        message_data = {
            'id': uuidutils.generate_uuid(),
            'project_id': 'x' * 255,
            'request_id': 'x' * 255,
            'resource_type': 'x' * 255,
            'resource_id': 'y' * 36,
            'action_id': 'y' * 10,
            'detail_id': 'y' * 10,
            'message_level': 'x' * 255,
            'created_at': datetime.datetime(2017, 7, 10, 18, 5, 58),
            'updated_at': None,
            'deleted_at': None,
            'deleted': 0,
            'expires_at': datetime.datetime(2017, 7, 11, 18, 5, 58),
        }

        new_table = utils.load_table(self.new_table_name, engine)
        engine.execute(new_table.insert(message_data))

    def check_downgrade(self, engine):
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    'messages', engine)


@map_to_migration('b516de97bfee')
class ProjectShareTypesQuotasChecks(BaseMigrationChecks):
    new_table_name = 'project_share_type_quotas'
    usages_table = 'quota_usages'
    reservations_table = 'reservations'
    st_record_id = uuidutils.generate_uuid()

    def setup_upgrade_data(self, engine):
        # Create share type
        self.st_data = {
            'id': self.st_record_id,
            'name': uuidutils.generate_uuid(),
            'deleted': "False",
        }
        st_table = utils.load_table('share_types', engine)
        engine.execute(st_table.insert(self.st_data))

    def check_upgrade(self, engine, data):
        # Create share type quota
        self.quota_data = {
            'project_id': 'x' * 255,
            'resource': 'y' * 255,
            'hard_limit': 987654321,
            'created_at': datetime.datetime(2017, 4, 11, 18, 5, 58),
            'updated_at': None,
            'deleted_at': None,
            'deleted': 0,
            'share_type_id': self.st_record_id,
        }
        new_table = utils.load_table(self.new_table_name, engine)
        engine.execute(new_table.insert(self.quota_data))

        # Create usage record
        self.usages_data = {
            'project_id': 'x' * 255,
            'user_id': None,
            'share_type_id': self.st_record_id,
            'resource': 'y' * 255,
            'in_use': 13,
            'reserved': 15,
        }
        usages_table = utils.load_table(self.usages_table, engine)
        engine.execute(usages_table.insert(self.usages_data))

        # Create reservation record
        self.reservations_data = {
            'uuid': uuidutils.generate_uuid(),
            'usage_id': 1,
            'project_id': 'x' * 255,
            'user_id': None,
            'share_type_id': self.st_record_id,
            'resource': 'y' * 255,
            'delta': 13,
            'expire': datetime.datetime(2399, 4, 11, 18, 5, 58),
        }
        reservations_table = utils.load_table(self.reservations_table, engine)
        engine.execute(reservations_table.insert(self.reservations_data))

    def check_downgrade(self, engine):
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError,
            utils.load_table, self.new_table_name, engine)
        for table_name in (self.usages_table, self.reservations_table):
            table = utils.load_table(table_name, engine)
            db_result = engine.execute(table.select())
            self.test_case.assertGreater(db_result.rowcount, 0)
            for row in db_result:
                self.test_case.assertFalse(hasattr(row, 'share_type_id'))


@map_to_migration('829a09b0ddd4')
class FixProjectShareTypesQuotasUniqueConstraintChecks(BaseMigrationChecks):
    st_record_id = uuidutils.generate_uuid()

    def setup_upgrade_data(self, engine):
        # Create share type
        self.st_data = {
            'id': self.st_record_id,
            'name': uuidutils.generate_uuid(),
            'deleted': "False",
        }
        st_table = utils.load_table('share_types', engine)
        engine.execute(st_table.insert(self.st_data))

    def check_upgrade(self, engine, data):
        for project_id in ('x' * 255, 'x'):
            # Create share type quota
            self.quota_data = {
                'project_id': project_id,
                'resource': 'y' * 255,
                'hard_limit': 987654321,
                'created_at': datetime.datetime(2017, 4, 11, 18, 5, 58),
                'updated_at': None,
                'deleted_at': None,
                'deleted': 0,
                'share_type_id': self.st_record_id,
            }
            new_table = utils.load_table('project_share_type_quotas', engine)
            engine.execute(new_table.insert(self.quota_data))

    def check_downgrade(self, engine):
        pass


@map_to_migration('27cb96d991fa')
class NewDescriptionColumnChecks(BaseMigrationChecks):
    st_table_name = 'share_types'
    st_ids = ['share_type_id_fake_3_%d' % i for i in (1, 2)]

    def setup_upgrade_data(self, engine):
        # Create share type
        share_type_data = {
            'id': self.st_ids[0],
            'name': 'name_1',
        }
        st_table = utils.load_table(self.st_table_name, engine)
        engine.execute(st_table.insert(share_type_data))

    def check_upgrade(self, engine, data):
        st_table = utils.load_table(self.st_table_name, engine)
        for na in engine.execute(st_table.select()):
            self.test_case.assertTrue(hasattr(na, 'description'))

        share_type_data_ds = {
            'id': self.st_ids[1],
            'name': 'name_1',
            'description': 'description_1',
        }
        engine.execute(st_table.insert(share_type_data_ds))
        st = engine.execute(st_table.select().where(
            share_type_data_ds['id'] == st_table.c.id)).first()
        self.test_case.assertEqual(
            share_type_data_ds['description'], st['description'])

    def check_downgrade(self, engine):
        table = utils.load_table(self.st_table_name, engine)
        db_result = engine.execute(table.select())
        for record in db_result:
            self.test_case.assertFalse(hasattr(record, 'description'))


@map_to_migration('4a482571410f')
class BackenInfoTableChecks(BaseMigrationChecks):
    new_table_name = 'backend_info'

    def setup_upgrade_data(self, engine):
        pass

    def check_upgrade(self, engine, data):
        data = {
            'host': 'test_host',
            'info_hash': 'test_hash',
            'created_at': datetime.datetime(2017, 7, 10, 18, 5, 58),
            'updated_at': None,
            'deleted_at': None,
            'deleted': 0,
        }

        new_table = utils.load_table(self.new_table_name, engine)
        engine.execute(new_table.insert(data))

    def check_downgrade(self, engine):
        self.test_case.assertRaises(sa_exc.NoSuchTableError, utils.load_table,
                                    self.new_table_name, engine)


@map_to_migration('579c267fbb4d')
class ShareInstanceAccessMapTableChecks(BaseMigrationChecks):
    share_access_table = 'share_access_map'
    share_instance_access_table = 'share_instance_access_map'

    @staticmethod
    def generate_share_instance(share_id, **kwargs):
        share_instance_data = {
            'id': uuidutils.generate_uuid(),
            'deleted': 'False',
            'host': 'fake',
            'share_id': share_id,
            'status': constants.STATUS_AVAILABLE,
        }
        share_instance_data.update(**kwargs)
        return share_instance_data

    @staticmethod
    def generate_share_access_map(share_id, **kwargs):
        share_access_data = {
            'id': uuidutils.generate_uuid(),
            'share_id': share_id,
            'deleted': 'False',
            'access_type': 'ip',
            'access_to': '192.0.2.10',
        }
        share_access_data.update(**kwargs)
        return share_access_data

    def setup_upgrade_data(self, engine):
        share = {
            'id': uuidutils.generate_uuid(),
            'share_proto': 'fake',
            'size': 1,
            'snapshot_id': None,
            'user_id': 'fake',
            'project_id': 'fake'
        }
        share_table = utils.load_table('shares', engine)
        engine.execute(share_table.insert(share))

        share_instances = [
            self.generate_share_instance(share['id']),
            self.generate_share_instance(share['id']),
        ]

        share_instance_table = utils.load_table('share_instances', engine)
        for share_instance in share_instances:
            engine.execute(share_instance_table.insert(share_instance))

        share_accesses = [
            self.generate_share_access_map(
                share['id'], state=constants.ACCESS_STATE_ACTIVE),
            self.generate_share_access_map(
                share['id'], state=constants.ACCESS_STATE_ERROR),
        ]
        self.active_share_access = share_accesses[0]
        self.error_share_access = share_accesses[1]
        share_access_table = utils.load_table('share_access_map', engine)
        engine.execute(share_access_table.insert(share_accesses))

    def check_upgrade(self, engine, data):
        share_access_table = utils.load_table(
            self.share_access_table, engine)
        share_instance_access_table = utils.load_table(
            self.share_instance_access_table, engine)
        share_accesses = engine.execute(share_access_table.select())
        share_instance_accesses = engine.execute(
            share_instance_access_table.select())

        for share_access in share_accesses:
            self.test_case.assertFalse(hasattr(share_access, 'state'))

        for si_access in share_instance_accesses:
            if si_access['access_id'] in (self.active_share_access['id'],
                                          self.error_share_access['id']):
                self.test_case.assertIn(si_access['state'],
                                        (self.active_share_access['state'],
                                         self.error_share_access['state']))

    def check_downgrade(self, engine):
        self.test_case.assertRaises(
            sa_exc.NoSuchTableError, utils.load_table,
            self.share_instance_access_table, engine)

        share_access_table = utils.load_table(
            self.share_access_table, engine)
        share_accesses = engine.execute(share_access_table.select().where(
            share_access_table.c.id.in_((self.active_share_access['id'],
                                         self.error_share_access['id']))))

        for share_access in share_accesses:
            self.test_case.assertTrue(hasattr(share_access, 'state'))
            if share_access['id'] == self.active_share_access['id']:
                self.test_case.assertEqual(
                    constants.ACCESS_STATE_ACTIVE, share_access['state'])
            elif share_access['id'] == self.error_share_access['id']:
                self.test_case.assertEqual(
                    constants.ACCESS_STATE_ERROR, share_access['state'])
