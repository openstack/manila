# Copyright 2014 Mirantis Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

import alembic
from alembic import config as alembic_config
import alembic.migration as alembic_migration
from oslo_config import cfg

from manila.db.sqlalchemy import api as db_api

CONF = cfg.CONF


def _alembic_config():
    path = os.path.join(os.path.dirname(__file__), os.pardir, 'alembic.ini')
    config = alembic_config.Config(path)
    return config


def version():
    """Current database version.

    :returns: Database version
    :rtype: string
    """
    engine = db_api.get_engine()
    with engine.connect() as conn:
        context = alembic_migration.MigrationContext.configure(conn)
        return context.get_current_revision()


def upgrade(revision):
    """Upgrade database.

    :param version: Desired database version
    :type version: string
    """
    return alembic.command.upgrade(_alembic_config(), revision or 'head')


def downgrade(revision):
    """Downgrade database.

    :param version: Desired database version
    :type version: string
    """
    return alembic.command.downgrade(_alembic_config(), revision or 'base')


def stamp(revision):
    """Stamp database with provided revision.

    Don't run any migrations.

    :param revision: Should match one from repository or head - to stamp
    database with most recent revision
    :type revision: string
    """
    return alembic.command.stamp(_alembic_config(), revision or 'head')


def revision(message=None, autogenerate=False):
    """Create template for migration.

    :param message: Text that will be used for migration title
    :type message: string
    :param autogenerate: If True - generates diff based on current database
    state
    :type autogenerate: bool
    """
    return alembic.command.revision(_alembic_config(), message, autogenerate)
