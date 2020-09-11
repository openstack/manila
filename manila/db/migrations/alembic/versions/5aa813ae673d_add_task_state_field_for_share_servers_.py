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

"""Add task_state field for share servers table

Revision ID: 5aa813ae673d
Revises: e6d88547b381
Create Date: 2020-06-23 12:04:47.821793

"""

# revision identifiers, used by Alembic.
revision = '5aa813ae673d'
down_revision = 'e6d88547b381'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


share_servers_fk_name = (
    "fk_share_servers_source_share_server_id")


def upgrade():

    try:
        op.add_column('share_servers', sa.Column(
            'task_state', sa.String(length=255), default=None))
        op.add_column(
            'share_servers', sa.Column(
                'source_share_server_id', sa.String(length=36),
                sa.ForeignKey('share_servers.id', name=share_servers_fk_name),
                default=None,
                nullable=True))

    except Exception:
        LOG.error("Column share_servers.task_state and/or "
                  "share_server.source_share_server_id not created!")
        raise


def downgrade():
    try:
        op.drop_column('share_servers', 'task_state')
        op.drop_constraint(share_servers_fk_name, 'share_servers',
                           type_='foreignkey')
        op.drop_column('share_servers', 'source_share_server_id')
    except Exception:
        LOG.error("Column share_servers.task_state and/or "
                  "share_servers.source_share_server_id not dropped!")
        raise
