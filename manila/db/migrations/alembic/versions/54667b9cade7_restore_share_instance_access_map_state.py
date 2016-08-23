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

"""add_share_instance_access_map_state

Revision ID: 54667b9cade7
Revises: 87ce15c59bbe
Create Date: 2016-09-02 10:18:07.290461

"""

# revision identifiers, used by Alembic.
revision = '54667b9cade7'
down_revision = '87ce15c59bbe'

from alembic import op
from sqlalchemy import Column, String

from manila.common import constants
from manila.db.migrations import utils


# Mapping for new value to be assigned as ShareInstanceAccessMapping's state
access_rules_status_to_state_mapping = {
    constants.STATUS_ACTIVE: constants.ACCESS_STATE_ACTIVE,
    constants.STATUS_OUT_OF_SYNC: constants.ACCESS_STATE_QUEUED_TO_APPLY,
    'updating': constants.ACCESS_STATE_QUEUED_TO_APPLY,
    'updating_multiple': constants.ACCESS_STATE_QUEUED_TO_APPLY,
    constants.STATUS_ERROR: constants.ACCESS_STATE_ERROR,
}

# Mapping for changes to Share Instance's access_rules_status
access_rules_status_upgrade_mapping = {
    constants.STATUS_ACTIVE: constants.STATUS_ACTIVE,
    constants.STATUS_OUT_OF_SYNC: constants.SHARE_INSTANCE_RULES_SYNCING,
    'updating': constants.SHARE_INSTANCE_RULES_SYNCING,
    'updating_multiple': constants.SHARE_INSTANCE_RULES_SYNCING,
    constants.STATUS_ERROR: constants.STATUS_ERROR,
}


def upgrade():
    op.add_column('share_instance_access_map',
                  Column('state', String(length=255),
                         default=constants.ACCESS_STATE_QUEUED_TO_APPLY))

    connection = op.get_bind()
    share_instances_table = utils.load_table('share_instances', connection)
    instance_access_map_table = utils.load_table('share_instance_access_map',
                                                 connection)

    instances_query = (
        share_instances_table.select().where(
            share_instances_table.c.status ==
            constants.STATUS_AVAILABLE).where(
            share_instances_table.c.deleted == 'False')
    )

    for instance in connection.execute(instances_query):
        access_rule_status = instance['access_rules_status']
        op.execute(
            instance_access_map_table.update().where(
                instance_access_map_table.c.share_instance_id == instance['id']
            ).values({
                'state': access_rules_status_to_state_mapping[
                    access_rule_status],
            })
        )
        op.execute(
            share_instances_table.update().where(
                share_instances_table.c.id == instance['id']
            ).values({
                'access_rules_status': access_rules_status_upgrade_mapping[
                    access_rule_status],
            })
        )


def downgrade():
    op.drop_column('share_instance_access_map', 'state')

    connection = op.get_bind()
    share_instances_table = utils.load_table('share_instances', connection)

    op.execute(
        share_instances_table.update().where(
            share_instances_table.c.access_rules_status ==
            constants.SHARE_INSTANCE_RULES_SYNCING).values({
                'access_rules_status': constants.STATUS_OUT_OF_SYNC})
    )
