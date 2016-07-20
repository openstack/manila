# Copyright 2016, Hitachi Data Systems.
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


"""move_share_type_id_to_instances

Revision ID: 48a7beae3117
Revises: 63809d875e32
Create Date: 2016-07-19 13:04:50.035139

"""

# revision identifiers, used by Alembic.
revision = '48a7beae3117'
down_revision = '63809d875e32'

from alembic import op
import sqlalchemy as sa

from manila.db.migrations import utils


def upgrade():
    """Move share_type_id from Shares to Share Instances table."""

    # NOTE(ganso): Adding share_type_id as a foreign key to share_instances
    # table. Please note that share_type_id is NOT a foreign key in shares
    # table prior to this migration.
    op.add_column(
        'share_instances',
        sa.Column('share_type_id', sa.String(36),
                  sa.ForeignKey('share_types.id', name='si_st_id_fk'),
                  nullable=True))
    connection = op.get_bind()
    shares_table = utils.load_table('shares', connection)
    share_instances_table = utils.load_table('share_instances', connection)

    for instance in connection.execute(share_instances_table.select()):
        share = connection.execute(shares_table.select().where(
            instance['share_id'] == shares_table.c.id)).first()
        op.execute(share_instances_table.update().where(
            share_instances_table.c.id == instance['id']).values(
            {'share_type_id': share['share_type_id']}))

    op.drop_column('shares', 'share_type_id')


def downgrade():
    """Move share_type_id from Share Instances to Shares table.

    This method can lead to data loss because only the share_type_id from the
    first share instance is moved to the shares table.
    """

    # NOTE(ganso): Adding back share_type_id to the shares table NOT as a
    # foreign key, as it was before.
    op.add_column(
        'shares',
        sa.Column('share_type_id', sa.String(36), nullable=True))
    connection = op.get_bind()
    shares_table = utils.load_table('shares', connection)
    share_instances_table = utils.load_table('share_instances', connection)

    for share in connection.execute(shares_table.select()):
        instance = connection.execute(share_instances_table.select().where(
            share['id'] == share_instances_table.c.share_id)).first()
        op.execute(shares_table.update().where(
            shares_table.c.id == instance['share_id']).values(
            {'share_type_id': instance['share_type_id']}))

    op.drop_constraint('si_st_id_fk', 'share_instances', type_='foreignkey')
    op.drop_column('share_instances', 'share_type_id')
