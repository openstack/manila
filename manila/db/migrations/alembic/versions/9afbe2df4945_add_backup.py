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

"""add backup

Revision ID: 9afbe2df4945
Revises: aebe2a413e13
Create Date: 2022-04-21 23:06:59.144695

"""

# revision identifiers, used by Alembic.
revision = '9afbe2df4945'
down_revision = 'aebe2a413e13'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)

share_backups_table_name = 'share_backups'


def upgrade():
    """Add backup attributes."""

    try:
        op.create_table(
            share_backups_table_name,
            sa.Column('id', sa.String(length=36),
                      primary_key=True, nullable=False),
            sa.Column('created_at', sa.DateTime),
            sa.Column('updated_at', sa.DateTime),
            sa.Column('deleted_at', sa.DateTime),
            sa.Column('deleted', sa.String(length=36), default='False'),
            sa.Column('user_id', sa.String(255)),
            sa.Column('project_id', sa.String(255)),
            sa.Column('availability_zone', sa.String(255)),
            sa.Column('fail_reason', sa.String(255)),
            sa.Column('display_name', sa.String(255)),
            sa.Column('display_description', sa.String(255)),
            sa.Column('host', sa.String(255)),
            sa.Column('topic', sa.String(255)),
            sa.Column('status', sa.String(255)),
            sa.Column('progress', sa.String(32)),
            sa.Column('restore_progress', sa.String(32)),
            sa.Column('size', sa.Integer),
            sa.Column('share_id', sa.String(36),
                      sa.ForeignKey('shares.id',
                                    name="fk_backups_share_id_shares")),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!",
                  share_backups_table_name)
        raise

    try:
        op.add_column(
            'shares',
            sa.Column('source_backup_id', sa.String(36), nullable=True))
    except Exception:
        LOG.error("Column can not be added for 'shares' table!")
        raise


def downgrade():
    """Remove share backup attributes and table share_backups."""
    try:
        op.drop_table(share_backups_table_name)
    except Exception:
        LOG.error("%s table not dropped.", share_backups_table_name)
        raise

    try:
        op.drop_column('shares', 'source_backup_id')
    except Exception:
        LOG.error("Column can not be dropped for 'shares' table!")
        raise
