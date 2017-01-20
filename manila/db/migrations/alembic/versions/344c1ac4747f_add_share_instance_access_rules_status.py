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

"""Remove access rules status and add access_rule_status to share_instance
model

Revision ID: 344c1ac4747f
Revises: dda6de06349
Create Date: 2015-11-18 14:58:55.806396

"""

# revision identifiers, used by Alembic.
revision = '344c1ac4747f'
down_revision = 'dda6de06349'

from alembic import op
from sqlalchemy import Column, String

from manila.common import constants
from manila.db.migrations import utils


priorities = {
    'active': 0,
    'new': 1,
    'error': 2
}

upgrade_data_mapping = {
    'active': 'active',
    'new': 'out_of_sync',
    'error': 'error',
}


def upgrade():
    """Transform individual access rules states to 'access_rules_status'.

    WARNING: This method performs lossy converting of existing data in DB.
    """
    op.add_column(
        'share_instances',
        Column('access_rules_status', String(length=255))
    )

    connection = op.get_bind()
    share_instances_table = utils.load_table('share_instances', connection)
    instance_access_table = utils.load_table('share_instance_access_map',
                                             connection)

    # NOTE(u_glide): Data migrations shouldn't be performed on live clouds
    # because it will lead to unpredictable behaviour of running operations
    # like migration.
    instances_query = (
        share_instances_table.select()
        .where(share_instances_table.c.status == constants.STATUS_AVAILABLE)
        .where(share_instances_table.c.deleted == 'False')
    )

    for instance in connection.execute(instances_query):

        access_mappings_query = instance_access_table.select().where(
            instance_access_table.c.share_instance_id == instance['id']
        ).where(instance_access_table.c.deleted == 'False')

        status = constants.STATUS_ACTIVE

        for access_rule in connection.execute(access_mappings_query):

            if (access_rule['state'] == constants.STATUS_DELETING or
                    access_rule['state'] not in priorities):
                continue

            if priorities[access_rule['state']] > priorities[status]:
                status = access_rule['state']

        op.execute(
            share_instances_table.update().where(
                share_instances_table.c.id == instance['id']
            ).values({'access_rules_status': upgrade_data_mapping[status]})
        )

    op.drop_column('share_instance_access_map', 'state')


def downgrade():
    op.add_column(
        'share_instance_access_map',
        Column('state', String(length=255))
    )

    connection = op.get_bind()
    share_instances_table = utils.load_table('share_instances', connection)
    instance_access_table = utils.load_table('share_instance_access_map',
                                             connection)

    instances_query = (
        share_instances_table.select()
        .where(share_instances_table.c.status == constants.STATUS_AVAILABLE)
        .where(share_instances_table.c.deleted == 'False')
    )

    for instance in connection.execute(instances_query):

        # NOTE(u_glide): We cannot determine if a rule is applied or not in
        # Manila, so administrator should manually handle such access rules.
        if instance['access_rules_status'] == 'active':
            state = 'active'
        else:
            state = 'error'

        op.execute(
            instance_access_table.update().where(
                instance_access_table.c.share_instance_id == instance['id']
            ).where(instance_access_table.c.deleted == 'False').values(
                {'state': state}
            )
        )

    op.drop_column('share_instances', 'access_rules_status')
