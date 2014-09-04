# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 OpenStack, LLC
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
Tests for database migrations.
"""

from alembic import script
import mock
from oslo.db.sqlalchemy import test_base
from oslo.db.sqlalchemy import test_migrations
from sqlalchemy.sql import text

from manila.db.migrations.alembic import migration
from manila.openstack.common import log as logging

LOG = logging.getLogger('manila.tests.test_migrations')


class ManilaMigrationsCheckers(test_migrations.WalkVersionsMixin):
    """Test sqlalchemy-migrate migrations."""

    snake_walk = False
    downgrade = False

    @property
    def INIT_VERSION(self):
        pass

    @property
    def REPOSITORY(self):
        pass

    @property
    def migration_api(self):
        return migration

    @property
    def migrate_engine(self):
        return self.engine

    def _walk_versions(self, snake_walk=False, downgrade=True):
        # Determine latest version script from the repo, then
        # upgrade from 1 through to the latest, with no data
        # in the databases. This just checks that the schema itself
        # upgrades successfully.

        # Place the database under version control
        alembic_cfg = migration._alembic_config()
        script_directory = script.ScriptDirectory.from_config(alembic_cfg)

        self.assertIsNone(self.migration_api.version())

        versions = [ver for ver in script_directory.walk_revisions()]

        LOG.debug('latest version is %s', versions[0].revision)

        prev_version = 'base'
        for version in reversed(versions):
            self._migrate_up(version.revision, with_data=True)
            if snake_walk and prev_version:
                downgraded = self._migrate_down(prev_version, with_data=True)
                if downgraded:
                    self._migrate_up(version.revision)
            prev_version = version.revision

        prev_version = 'base'
        if downgrade:
            for version in versions:
                self._migrate_down(version.revision)
                downgraded = self._migrate_down(prev_version)
                if snake_walk and downgraded:
                    self._migrate_up(version.revision)
                    self._migrate_down(prev_version)
                prev_version = version.revision

    def _migrate_down(self, version, with_data=False):
        try:
            self.migration_api.downgrade(version)
        except NotImplementedError:
            # NOTE(sirp): some migrations, namely release-level
            # migrations, don't support a downgrade.
            return False

        self.assertEqual(version, self.migration_api.version())

        # NOTE(sirp): `version` is what we're downgrading to (i.e. the 'target'
        # version). So if we have any downgrade checks, they need to be run for
        # the previous (higher numbered) migration.
        if with_data:
            post_downgrade = getattr(
                self, "_post_downgrade_%s" % (version), None)
            if post_downgrade:
                post_downgrade(self.engine)

        return True

    def _migrate_up(self, version, with_data=False):
        """migrate up to a new version of the db.

        We allow for data insertion and post checks at every
        migration version with special _pre_upgrade_### and
        _check_### functions in the main test.
        """
        # NOTE(sdague): try block is here because it's impossible to debug
        # where a failed data migration happens otherwise
        try:
            if with_data:
                data = None
                pre_upgrade = getattr(
                    self, "_pre_upgrade_%s" % version, None)
                if pre_upgrade:
                    data = pre_upgrade(self.engine)

            self.migration_api.upgrade(version)
            self.assertEqual(version, self.migration_api.version())
            if with_data:
                check = getattr(self, "_check_%s" % version, None)
                if check:
                    check(self.engine, data)
        except Exception as e:
            LOG.error(_("Failed to migrate to version %(version)s on engine "
                        "%(engine)s. Exception while running the migration: "
                        "%(exception)s"), {'version': version,
                                           'engine': self.engine,
                                           'exception': e})
            raise

    def test_walk_versions(self):
        """Walks all version scripts for each tested database.

        While walking, ensur that there are no errors in the version
        scripts for each engine.
        """
        with mock.patch('manila.db.sqlalchemy.api.get_engine',
                        return_value=self.engine):
            self._walk_versions(snake_walk=self.snake_walk,
                                downgrade=self.downgrade)


class TestManilaMigrationsMySQL(ManilaMigrationsCheckers,
                                test_base.MySQLOpportunisticTestCase):
    """Run migration tests on MySQL backend."""

    def test_mysql_innodb(self):
        """Test that table creation on mysql only builds InnoDB tables."""
        with mock.patch('manila.db.sqlalchemy.api.get_engine',
                        return_value=self.engine):
            self._walk_versions(snake_walk=False, downgrade=False)

        # sanity check
        sanity_check = """SELECT count(*)
                          FROM information_schema.tables
                          WHERE table_schema = :database;"""
        total = self.engine.execute(
            text(sanity_check),
            database=self.engine.url.database)

        self.assertTrue(total.scalar() > 0, "No tables found. Wrong schema?")

        noninnodb_query = """
            SELECT count(*)
            FROM information_schema.TABLES
            WHERE table_schema = :database
                AND engine != 'InnoDB'
                AND table_name != 'alembic_version';"""

        count = self.engine.execute(
            text(noninnodb_query),
            database=self.engine.url.database
        ).scalar()
        self.assertEqual(count, 0, "%d non InnoDB tables created" % count)


class TestManilaMigrationsPostgreSQL(
        ManilaMigrationsCheckers, test_base.PostgreSQLOpportunisticTestCase):
    """Run migration tests on PostgreSQL backend."""


class TestManilaMigrationsSQLite(ManilaMigrationsCheckers,
                                 test_base.DbTestCase):
    """Run migration tests on SQLite backend."""
