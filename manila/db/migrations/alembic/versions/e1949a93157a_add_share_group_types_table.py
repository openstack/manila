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

"""Add share group types table

Revision ID: e1949a93157a
Revises: 03da71c0e321
Create Date: 2016-06-01 10:41:06.410945

"""

# revision identifiers, used by Alembic.
revision = 'e1949a93157a'
down_revision = '03da71c0e321'

from alembic import op
from oslo_log import log
import sqlalchemy as sql


LOG = log.getLogger(__name__)


def upgrade():
    meta = sql.MetaData()
    meta.bind = op.get_bind()

    # Add share group types
    try:
        op.create_table(
            'share_group_types',
            sql.Column(
                'id', sql.String(length=36), primary_key=True, nullable=False),
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('is_public', sql.Boolean()),
            sql.Column('name', sql.String(length=255)),
            sql.Column('deleted', sql.String(length=36)),
            sql.UniqueConstraint(
                'name', 'deleted', name="uniq_share_group_type_name"),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'share_group_types')
        raise

    # Add share group specs
    try:
        op.create_table(
            'share_group_type_specs',
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('spec_key', sql.String(length=255)),
            sql.Column('spec_value', sql.String(length=255)),
            sql.Column('deleted', sql.Integer),
            sql.Column(
                'share_group_type_id', sql.String(36),
                sql.ForeignKey(
                    'share_group_types.id', name="sgtp_id_extra_specs_fk")),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'share_group_type_specs')
        raise

    # Add share group project types
    try:
        op.create_table(
            'share_group_type_projects',
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column(
                'share_group_type_id', sql.String(36),
                sql.ForeignKey('share_group_types.id', name="sgtp_id_fk")),
            sql.Column('project_id', sql.String(length=255)),
            sql.Column('deleted', sql.Integer),
            sql.UniqueConstraint(
                'share_group_type_id', 'project_id', 'deleted',
                name="sgtp_project_id_uc"),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'share_group_type_projects')
        raise

    # Add mapping between group types and share types

    op.create_table(
        'share_group_type_share_type_mappings',
        sql.Column('id', sql.String(36), primary_key=True, nullable=False),
        sql.Column('created_at', sql.DateTime),
        sql.Column('updated_at', sql.DateTime),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('deleted', sql.String(36), default='False'),
        sql.Column(
            'share_group_type_id', sql.String(length=36),
            sql.ForeignKey('share_group_types.id', name="sgtp_id_sgt_id_uc"),
            nullable=False),
        sql.Column(
            'share_type_id', sql.String(length=36),
            sql.ForeignKey('share_types.id', name="sgtp_id_st_id_uc"),
            nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    # Add share group type for share groups
    op.add_column(
        'share_groups',
        sql.Column(
            'share_group_type_id', sql.String(36),
            sql.ForeignKey('share_group_types.id', name="sgt_id_sg_id_uc"),
        )
    )

    # TODO(ameade): Create type for existing consistency groups


def downgrade():
    # Remove share group type for share groups
    op.drop_constraint("sgt_id_sg_id_uc", "share_groups", type_="foreignkey")
    op.drop_column('share_groups', 'share_group_type_id')

    # Drop mappings
    for table_name in ('share_group_type_share_type_mappings',
                       'share_group_type_projects',
                       'share_group_type_specs', 'share_group_types'):
        try:
            op.drop_table(table_name)
        except Exception:
            LOG.error("%s table not dropped", table_name)
            raise
