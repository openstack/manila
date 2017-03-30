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

"""Add_share_type_projects

Revision ID: ef0c02b4366
Revises: 17115072e1c3
Create Date: 2015-02-20 10:49:40.744974

"""

# revision identifiers, used by Alembic.
revision = 'ef0c02b4366'
down_revision = '59eb64046740'

from alembic import op
from oslo_log import log
import sqlalchemy as sql


LOG = log.getLogger(__name__)


def upgrade():
    meta = sql.MetaData()
    meta.bind = op.get_bind()
    is_public = sql.Column('is_public', sql.Boolean)

    try:
        op.add_column('share_types', is_public)

        share_types = sql.Table('share_types', meta, is_public.copy())
        share_types.update().values(is_public=True).execute()
    except Exception:
        LOG.error("Column |%s| not created!", repr(is_public))
        raise

    try:
        op.create_table(
            'share_type_projects',
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('share_type_id', sql.String(36),
                       sql.ForeignKey('share_types.id', name="stp_id_fk")),
            sql.Column('project_id', sql.String(length=255)),
            sql.Column('deleted', sql.Integer),
            sql.UniqueConstraint('share_type_id', 'project_id', 'deleted',
                                 name="stp_project_id_uc"),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'share_type_projects')
        raise


def downgrade():
    try:
        op.drop_column('share_types', 'is_public')
    except Exception:
        LOG.error("share_types.is_public column not dropped")
        raise

    try:
        op.drop_table('share_type_projects')
    except Exception:
        LOG.error("share_type_projects table not dropped")
        raise
