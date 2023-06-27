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

"""add_resource_locks

Revision ID: cb20f743ca7b
Revises: 9afbe2df4945
Create Date: 2023-06-23 16:34:36.277477

"""

# revision identifiers, used by Alembic.
revision = 'cb20f743ca7b'
down_revision = '9afbe2df4945'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)
    try:
        op.create_table(
            'resource_locks',
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('user_id', sa.String(255), nullable=False),
            sa.Column('project_id', sa.String(255), nullable=False),
            sa.Column('resource_action', sa.String(255), default='delete'),
            sa.Column('resource_type', sa.String(255), nullable=False),
            sa.Column('resource_id', sa.String(36), nullable=False),
            sa.Column('lock_context', sa.String(16), nullable=False),
            sa.Column('lock_reason', sa.String(1023), nullable=True),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.String(36), default='False'),
            mysql_engine='InnoDB',
            mysql_charset='utf8',
        )
    except Exception:
        LOG.error("Table resource_locks not created!")
        raise


def downgrade():
    try:
        op.drop_table('resource_locks')
    except Exception:
        LOG.error("resource_locks table not dropped")
        raise
