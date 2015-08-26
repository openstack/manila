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

"""add_share_instances_access_map

Revision ID: 579c267fbb4d
Revises: 5077ffcc5f1c
Create Date: 2015-08-19 07:51:52.928542

"""

# revision identifiers, used by Alembic.
revision = '579c267fbb4d'
down_revision = '5077ffcc5f1c'

from alembic import op
from sqlalchemy import Column, DateTime, ForeignKey, String
from oslo_utils import uuidutils

from manila.db.migrations import utils


def upgrade():
    """Create 'share_instance_access_map' table and move 'state' column."""

    instance_access_table = op.create_table(
        'share_instance_access_map',
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', String(length=36), default='False'),
        Column('id', String(length=36), primary_key=True, nullable=False),
        Column('share_instance_id', String(length=36),
               ForeignKey('share_instances.id', name="siam_instance_fk")),
        Column('access_id', String(length=36),
               ForeignKey('share_access_map.id', name="siam_access_fk")),
        Column('state', String(length=255)),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    # NOTE(u_glide): Move all states from 'share_access_map'
    # to 'share_instance_access_map'
    instance_access_mappings = []
    connection = op.get_bind()
    access_table = utils.load_table('share_access_map', connection)
    instances_table = utils.load_table('share_instances', connection)

    for access_rule in connection.execute(access_table.select()):
        instances_query = instances_table.select().where(
            instances_table.c.share_id == access_rule.share_id
        )

        for instance in connection.execute(instances_query):
            instance_access_mappings.append({
                'created_at': access_rule.created_at,
                'updated_at': access_rule.updated_at,
                'deleted_at': access_rule.deleted_at,
                'deleted': access_rule.deleted,
                'id': uuidutils.generate_uuid(),
                'share_instance_id': instance.id,
                'access_id': access_rule.id,
                'state': access_rule.state,
            })
    op.bulk_insert(instance_access_table, instance_access_mappings)
    op.drop_column('share_access_map', 'state')


def downgrade():
    """Remove 'share_instance_access_map' table and add 'state' column back.

    This method can lead to data loss because only first state is saved in
    share_access_map table.
    """
    op.add_column('share_access_map', Column('state', String(length=255)))

    # NOTE(u_glide): Move all states from 'share_instance_access_map'
    # to 'share_access_map'
    connection = op.get_bind()
    access_table = utils.load_table('share_access_map', connection)
    instance_access_table = utils.load_table('share_instance_access_map',
                                             connection)

    for access_rule in connection.execute(access_table.select()):
        access_mapping = connection.execute(
            instance_access_table.select().where(
                instance_access_table.c.deleted == "False").where(
                instance_access_table.c.access_id == access_rule['id'])
        ).first()

        op.execute(
            access_table.update().where(
                access_table.c.id == access_rule['id']
            ).values({'state': access_mapping['state']})
        )

    op.drop_table('share_instance_access_map')
