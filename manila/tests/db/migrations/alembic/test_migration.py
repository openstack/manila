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
from oslo_db.sqlalchemy import test_base
from oslo_db.sqlalchemy import test_migrations
from oslo_log import log
from sqlalchemy.sql import text

from manila.db.migrations.alembic import migration
from manila.tests.db.migrations.alembic import migrations_data_checks

LOG = log.getLogger('manila.tests.test_migrations')


class ManilaMigrationsCheckers(test_migrations.WalkVersionsMixin,
                               migrations_data_checks.DbMigrationsData):
    """Test alembic migrations."""

    @property
    def snake_walk(self):
        return True

    @property
    def downgrade(self):
        return True

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

        for version in reversed(versions):
            self._migrate_up(version.revision, with_data=True)
            if snake_walk:
                downgraded = self._migrate_down(
                    version, with_data=True)
                if downgraded:
                    self._migrate_up(version.revision)

        if downgrade:
            for version in versions:
                downgraded = self._migrate_down(version)
                if snake_walk and downgraded:
                    self._migrate_up(version.revision)
                    self._migrate_down(version)

    def _migrate_down(self, version, with_data=False):
        try:
            self.migration_api.downgrade(version.down_revision)
        except NotImplementedError:
            # NOTE(sirp): some migrations, namely release-level
            # migrations, don't support a downgrade.
            return False

        self.assertEqual(version.down_revision, self.migration_api.version())

        if with_data:
            post_downgrade = getattr(
                self, "_post_downgrade_%s" % version.revision, None)
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
            LOG.error("Failed to migrate to version %(version)s on engine "
                      "%(engine)s. Exception while running the migration: "
                      "%(exception)s", {'version': version,
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

    def test_single_branch(self):
        alembic_cfg = migration._alembic_config()
        script_directory = script.ScriptDirectory.from_config(alembic_cfg)

        actual_result = script_directory.get_heads()

        self.assertEqual(1, len(actual_result),
                         "Db migrations should have only one branch.")


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
        self.assertEqual(0, count, "%d non InnoDB tables created" % count)


class TestManilaMigrationsPostgreSQL(
        ManilaMigrationsCheckers, test_base.PostgreSQLOpportunisticTestCase):
    """Run migration tests on PostgreSQL backend."""
