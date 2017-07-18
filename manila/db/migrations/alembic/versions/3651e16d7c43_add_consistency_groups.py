# Copyright (c) 2015 Alex Meade
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

"""Create Consistency Groups Tables and Columns

Revision ID: 3651e16d7c43
Revises: 55761e5f59c5
Create Date: 2015-07-29 13:17:15.940454

"""

# revision identifiers, used by Alembic.
revision = '3651e16d7c43'
down_revision = '55761e5f59c5'

SHARE_NETWORK_FK_CONSTRAINT_NAME = "fk_cg_share_network_id"
SHARE_SERVER_FK_CONSTRAINT_NAME = "fk_cg_share_server_id"
SHARES_CG_FK_CONSTRAINT_NAME = "fk_shares_consistency_group_id"
CG_MAP_FK_CONSTRAINT_NAME = "fk_cgstm_cg_id"
SHARE_TYPE_FK_CONSTRAINT_NAME = "fk_cgstm_share_type_id"
CGSNAP_CG_ID_FK_CONSTRAINT_NAME = "fk_cgsnapshots_consistency_group_id"
CGSNAP_MEM_SHARETYPE_FK_CONSTRAINT_NAME = "fk_cgsnapshot_members_share_type_id"
CGSNAP_MEM_SNAP_ID_FK_CONSTRAINT_NAME = "fk_cgsnapshot_members_cgsnapshot_id"
CGSNAP_MEM_SHARE_FK_CONSTRAINT_NAME = "fk_cgsnapshot_members_share_id"
CGSNAP_MEM_INST_FK_CONSTRAINT_NAME = "fk_cgsnapshot_members_share_instance_id"

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    # New table - consistency_groups
    op.create_table(
        'consistency_groups',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),

        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=False),
        sa.Column('host', sa.String(length=255)),
        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=255)),
        sa.Column('status', sa.String(length=255)),
        sa.Column('source_cgsnapshot_id', sa.String(length=36)),
        sa.Column('share_network_id', sa.String(length=36),
                  sa.ForeignKey('share_networks.id',
                                name=SHARE_NETWORK_FK_CONSTRAINT_NAME),
                  nullable=True),
        sa.Column('share_server_id', sa.String(length=36),
                  sa.ForeignKey('share_servers.id',
                                name=SHARE_SERVER_FK_CONSTRAINT_NAME),
                  nullable=True),

        mysql_engine='InnoDB',
        mysql_charset='utf8')

    op.add_column(
        'shares',
        sa.Column('consistency_group_id',
                  sa.String(36),
                  sa.ForeignKey('consistency_groups.id',
                                name=SHARES_CG_FK_CONSTRAINT_NAME)))

    op.add_column('shares',
                  sa.Column('source_cgsnapshot_member_id', sa.String(36)))

    op.create_table(
        'consistency_group_share_type_mappings',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),

        sa.Column('consistency_group_id', sa.String(length=36),
                  sa.ForeignKey('consistency_groups.id',
                                name=CG_MAP_FK_CONSTRAINT_NAME),
                  nullable=False),
        sa.Column('share_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id',
                                name=SHARE_TYPE_FK_CONSTRAINT_NAME),
                  nullable=False),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    op.create_table(
        'cgsnapshots',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=False),

        sa.Column('consistency_group_id', sa.String(length=36),
                  sa.ForeignKey('consistency_groups.id',
                                name=CGSNAP_CG_ID_FK_CONSTRAINT_NAME),
                  nullable=False),

        sa.Column('name', sa.String(length=255)),
        sa.Column('description', sa.String(length=255)),
        sa.Column('status', sa.String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    op.create_table(
        'cgsnapshot_members',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=False),

        sa.Column('cgsnapshot_id', sa.String(length=36),
                  sa.ForeignKey('cgsnapshots.id',
                                name=CGSNAP_MEM_SNAP_ID_FK_CONSTRAINT_NAME),
                  nullable=False),
        sa.Column('share_instance_id', sa.String(length=36),
                  sa.ForeignKey('share_instances.id',
                                name=CGSNAP_MEM_INST_FK_CONSTRAINT_NAME),
                  nullable=False),
        sa.Column('share_id', sa.String(length=36),
                  sa.ForeignKey('shares.id',
                                name=CGSNAP_MEM_SHARE_FK_CONSTRAINT_NAME),
                  nullable=False),
        sa.Column('share_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id',
                                name=CGSNAP_MEM_SHARETYPE_FK_CONSTRAINT_NAME),
                  nullable=False),

        sa.Column('size', sa.Integer),
        sa.Column('status', sa.String(length=255)),
        sa.Column('share_proto', sa.String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')


def downgrade():
    try:
        op.drop_table('cgsnapshot_members')
    except Exception:
        LOG.exception("Error Dropping 'cgsnapshot_members' table.")

    try:
        op.drop_table('cgsnapshots')
    except Exception:
        LOG.exception("Error Dropping 'cgsnapshots' table.")

    try:
        op.drop_table('consistency_group_share_type_mappings')
    except Exception:
        LOG.exception("Error Dropping "
                      "'consistency_group_share_type_mappings' table.")

    try:
        op.drop_column('shares', 'source_cgsnapshot_member_id')
    except Exception:
        LOG.exception("Error Dropping 'source_cgsnapshot_member_id' "
                      "column from 'shares' table.")

    try:
        op.drop_constraint(SHARES_CG_FK_CONSTRAINT_NAME,
                           'shares',
                           type_='foreignkey')
    except Exception:
        LOG.exception("Error Dropping '%s' constraint.",
                      SHARES_CG_FK_CONSTRAINT_NAME)

    try:
        op.drop_column('shares', 'consistency_group_id')
    except Exception:
        LOG.exception("Error Dropping 'consistency_group_id' column "
                      "from 'shares' table.")

    try:
        op.drop_table('consistency_groups')
    except Exception:
        LOG.exception("Error Dropping 'consistency_groups' table.")
