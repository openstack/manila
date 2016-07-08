# Copyright (c) 2016 Hitachi Data Systems.
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

"""add_share_snapshot_access

Revision ID: a77e2ad5012d
Revises: e1949a93157a
Create Date: 2016-07-15 13:32:19.417771

"""

# revision identifiers, used by Alembic.
revision = 'a77e2ad5012d'
down_revision = 'e1949a93157a'

from manila.common import constants
from manila.db.migrations import utils

from alembic import op

import sqlalchemy as sa


def upgrade():
    op.create_table(
        'share_snapshot_access_map',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('share_snapshot_id', sa.String(36),
                  sa.ForeignKey('share_snapshots.id',
                                name='ssam_snapshot_fk')),
        sa.Column('access_type', sa.String(255)),
        sa.Column('access_to', sa.String(255))
    )

    op.create_table(
        'share_snapshot_instance_access_map',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('share_snapshot_instance_id', sa.String(36),
                  sa.ForeignKey('share_snapshot_instances.id',
                                name='ssiam_snapshot_instance_fk')),
        sa.Column('access_id', sa.String(36),
                  sa.ForeignKey('share_snapshot_access_map.id',
                                name='ssam_access_fk')),
        sa.Column('state', sa.String(255),
                  default=constants.ACCESS_STATE_QUEUED_TO_APPLY)
    )

    op.create_table(
        'share_snapshot_instance_export_locations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.String(36), default='False'),
        sa.Column('share_snapshot_instance_id', sa.String(36),
                  sa.ForeignKey('share_snapshot_instances.id',
                                name='ssiel_snapshot_instance_fk')),
        sa.Column('path', sa.String(2000)),
        sa.Column('is_admin_only', sa.Boolean, default=False, nullable=False)
    )

    op.add_column('shares',
                  sa.Column('mount_snapshot_support', sa.Boolean,
                            default=False))

    connection = op.get_bind()
    shares_table = utils.load_table('shares', connection)

    op.execute(
        shares_table.update().where(
            shares_table.c.deleted == 'False').values({
                'mount_snapshot_support': False,
            })
    )


def downgrade():
    op.drop_table('share_snapshot_instance_export_locations')
    op.drop_table('share_snapshot_instance_access_map')
    op.drop_table('share_snapshot_access_map')
    op.drop_column('shares', 'mount_snapshot_support')
