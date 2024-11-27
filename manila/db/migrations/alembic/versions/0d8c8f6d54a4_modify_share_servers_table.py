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

"""modify_share_servers_table

Revision ID: 0d8c8f6d54a4
Revises: cdefa6287df8
Create Date: 2024-11-15 09:25:25.957286

"""

# revision identifiers, used by Alembic.
revision = '0d8c8f6d54a4'
down_revision = 'cdefa6287df8'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


SHARE_SERVERS_TABLE = 'share_servers'
LOG = log.getLogger(__name__)


def upgrade():
    # add a new column to share_servers.
    try:
        op.add_column(
            SHARE_SERVERS_TABLE,
            sa.Column('share_replicas_migration_support', sa.Boolean,
                      nullable=False, server_default=sa.sql.false()))
    except Exception:
        LOG.error("Table %s could not add column "
                  "'share_replicas_migration_support'.",
                  SHARE_SERVERS_TABLE)
        raise


def downgrade():
    try:
        op.drop_column(SHARE_SERVERS_TABLE,
                       'share_replicas_migration_support')
    except Exception:
        LOG.error("Table %s failed to drop the column "
                  "'share_replicas_migration_support'.", SHARE_SERVERS_TABLE)
        raise
