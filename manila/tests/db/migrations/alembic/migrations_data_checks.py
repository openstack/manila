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

from oslo_utils import uuidutils
import six
from sqlalchemy import exc as sa_exc

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


@map_to_migration('1f0bd302c1a6')
class AvailabilityZoneMigrationChecks(BaseMigrationChecks):

    valid_az_names = ('az1', 'az2')

    def _get_service_data(self, options):
        base_dict = {
            'binary': 'manila-share',
            'topic': 'share',
            'disabled': '0',
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
            self.test_case.assertTrue(az.name in self.valid_az_names)
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
