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

"""add_cast_rules_to_readonly_to_share_instances

Revision ID: e9f79621d83f
Revises: 54667b9cade7
Create Date: 2016-12-01 04:06:33.115054

"""

# revision identifiers, used by Alembic.
revision = 'e9f79621d83f'
down_revision = '54667b9cade7'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

from manila.common import constants
from manila.db.migrations import utils

LOG = log.getLogger(__name__)


def upgrade():

    LOG.info("Adding cast_rules_to_readonly column to share instances.")

    op.add_column('share_instances',
                  sa.Column('cast_rules_to_readonly', sa.Boolean,
                            default=False))

    connection = op.get_bind()
    shares_table = utils.load_table('shares', connection)
    share_instances_table = utils.load_table('share_instances', connection)

    # First, set the value of ``cast_rules_to_readonly`` in every existing
    # share instance to False
    op.execute(
        share_instances_table.update().values({
            'cast_rules_to_readonly': False,
        })
    )

    # Set the value of ``cast_rules_to_readonly`` to True for secondary
    # replicas in 'readable' replication relationships
    replicated_shares_query = (
        shares_table.select()
        .where(shares_table.c.deleted == 'False')
        .where(shares_table.c.replication_type
               == constants.REPLICATION_TYPE_READABLE)
    )

    for replicated_share in connection.execute(replicated_shares_query):
        # NOTE (gouthamr): Only secondary replicas that are not undergoing a
        # 'replication_change' (promotion to active) are considered. When the
        # replication change is complete, the share manager will take care
        # of ensuring the correct values for the replicas that were involved
        # in the transaction.
        secondary_replicas_query = (
            share_instances_table.select().where(
                share_instances_table.c.deleted == 'False').where(
                share_instances_table.c.replica_state
                    != constants.REPLICA_STATE_ACTIVE).where(
                share_instances_table.c.status
                    != constants.STATUS_REPLICATION_CHANGE).where(
                replicated_share['id'] == share_instances_table.c.share_id
            )
        )
        for replica in connection.execute(secondary_replicas_query):
            op.execute(
                share_instances_table.update().where(
                    share_instances_table.c.id == replica.id
                ).values({
                    'cast_rules_to_readonly': True,
                })
            )

    op.alter_column('share_instances',
                    'cast_rules_to_readonly',
                    existing_type=sa.Boolean,
                    existing_server_default=False,
                    nullable=False)


def downgrade():
    LOG.info("Removing cast_rules_to_readonly column from share "
             "instances.")
    op.drop_column('share_instances', 'cast_rules_to_readonly')
