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

"""add_snapshot_metadata_table

Revision ID: bb5938d74b73
Revises: a87e0fb17dee
Create Date: 2022-01-14 14:36:59.408638

"""

# revision identifiers, used by Alembic.
revision = 'bb5938d74b73'
down_revision = 'a87e0fb17dee'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

LOG = log.getLogger(__name__)

share_snapshot_metadata_table_name = 'share_snapshot_metadata'


def upgrade():
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sql.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sql.DateTime)
    try:
        op.create_table(
            share_snapshot_metadata_table_name,
            sql.Column('deleted', sql.String(36), default='False'),
            sql.Column('created_at', datetime_type),
            sql.Column('updated_at', datetime_type),
            sql.Column('deleted_at', datetime_type),
            sql.Column('share_snapshot_id', sql.String(36),
                       sql.ForeignKey('share_snapshots.id'), nullable=False),
            sql.Column('key', sql.String(255), nullable=False),
            sql.Column('value', sql.String(1023), nullable=False),
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!",
                  share_snapshot_metadata_table_name)
        raise


def downgrade():
    try:
        op.drop_table(share_snapshot_metadata_table_name)
    except Exception:
        LOG.error("Table |%s| not dropped!",
                  share_snapshot_metadata_table_name)
        raise
