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

import os

from migrate.versioning import api as migration_api
from migrate.versioning import repository
from oslo.db.sqlalchemy import test_base
from oslo.db.sqlalchemy import test_migrations
from sqlalchemy.sql import text

import manila.db.sqlalchemy.migrate_repo


class ManilaMigrationsCheckers(test_migrations.WalkVersionsMixin):
    """Test sqlalchemy-migrate migrations."""

    snake_walk = False
    downgrade = False

    @property
    def INIT_VERSION(self):
        return 000

    @property
    def REPOSITORY(self):
        migrate_file = manila.db.sqlalchemy.migrate_repo.__file__
        return repository.Repository(
            os.path.abspath(os.path.dirname(migrate_file)))

    @property
    def migration_api(self):
        return migration_api

    @property
    def migrate_engine(self):
        return self.engine

    def test_walk_versions(self):
        """
        Walks all version scripts for each tested database, ensuring
        that there are no errors in the version scripts for each engine
        """
        self._walk_versions(snake_walk=self.snake_walk,
                            downgrade=self.downgrade)


class TestManilaMigrationsMySQL(ManilaMigrationsCheckers,
                                test_base.MySQLOpportunisticTestCase):
    """Run migration tests on MySQL backend."""

    def test_mysql_innodb(self):
        """Test that table creation on mysql only builds InnoDB tables."""
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
                AND table_name != 'migrate_version';"""

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
