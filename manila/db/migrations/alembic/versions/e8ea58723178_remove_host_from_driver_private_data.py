# Copyright (c) 2016 EMC Corporation.
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

"""Remove host from driver private data

Revision ID: e8ea58723178
Revises: fdfb668d19e1
Create Date: 2016-07-11 12:59:34.579291

"""

# revision identifiers, used by Alembic.
revision = 'e8ea58723178'
down_revision = 'fdfb668d19e1'

from alembic import op
from oslo_log import log
from oslo_utils import uuidutils
import sqlalchemy as sql

from manila.db.migrations import utils

LOG = log.getLogger(__name__)
TABLE_NAME = 'drivers_private_data'
COLUMN_HOST = 'host'
DEFAULT_HOST = 'unknown'
COLUMN_ENTITY = 'entity_uuid'
COLUMN_KEY = 'key'
MYSQL_ENGINE = 'mysql'


def upgrade():
    bind = op.get_bind()
    engine = bind.engine
    try:
        if (engine.name == MYSQL_ENGINE):
            op.drop_constraint('PRIMARY', TABLE_NAME, type_='primary')
            op.create_primary_key('DRIVERS_PRIVATE_PK', TABLE_NAME,
                                  ['entity_uuid', 'key'])
        op.drop_column(TABLE_NAME, COLUMN_HOST)
    except Exception:
        LOG.error("Column '%s' could not be dropped", COLUMN_HOST)
        raise


def downgrade():
    connection = op.get_bind()
    from_table = utils.load_table(TABLE_NAME, connection)
    migration_table_name = "_migrating_%(table)s_%(session)s" % {
        'table': TABLE_NAME,
        'session': uuidutils.generate_uuid()[:8]
    }

    LOG.info("Creating the migration table %(table)s", {
        'table': migration_table_name
    })
    migration_table = op.create_table(
        migration_table_name,
        sql.Column('created_at', sql.DateTime),
        sql.Column('updated_at', sql.DateTime),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('deleted', sql.Integer, default=0),
        sql.Column('host', sql.String(255),
                   nullable=False, primary_key=True),
        sql.Column('entity_uuid', sql.String(36),
                   nullable=False, primary_key=True),
        sql.Column('key', sql.String(255),
                   nullable=False, primary_key=True),
        sql.Column('value', sql.String(1023), nullable=False),
        mysql_engine='InnoDB',
    )

    LOG.info("Copying data from %(from_table)s to the migration "
             "table %(migration_table)s", {
                 'from_table': TABLE_NAME,
                 'migration_table': migration_table_name
             })
    rows = []
    for row in op.get_bind().execute(from_table.select()):
        rows.append({
            'created_at': row.created_at,
            'updated_at': row.updated_at,
            'deleted_at': row.deleted_at,
            'deleted': row.deleted,
            'host': DEFAULT_HOST,
            'entity_uuid': row.entity_uuid,
            'key': row.key,
            'value': row.value
        })
    op.bulk_insert(migration_table, rows)

    LOG.info("Dropping table %(from_table)s", {
        'from_table': TABLE_NAME
    })
    op.drop_table(TABLE_NAME)

    LOG.info("Rename the migration table %(migration_table)s to "
             "the original table %(from_table)s", {
                 'migration_table': migration_table_name,
                 'from_table': TABLE_NAME
             })
    op.rename_table(migration_table_name, TABLE_NAME)
