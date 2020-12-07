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

"""add_security_service_update_control_fields

Revision ID: 478c445d8d3e
Revises: 0c23aec99b74
Create Date: 2020-12-07 12:33:41.444202

"""

# revision identifiers, used by Alembic.
revision = '478c445d8d3e'
down_revision = '0c23aec99b74'

from alembic import op
from manila.common import constants
from oslo_log import log
import sqlalchemy as sa

SHARE_SERVERS_TABLE = 'share_servers'
SHARE_NETWORKS_TABLE = 'share_networks'
ASYNC_OPERATION_DATA_TABLE = 'async_operation_data'
LOG = log.getLogger(__name__)


def upgrade():
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)
    try:
        op.create_table(
            ASYNC_OPERATION_DATA_TABLE,
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.Integer, default=0),
            sa.Column('entity_uuid', sa.String(36),
                      nullable=False, primary_key=True),
            sa.Column('key', sa.String(255),
                      nullable=False, primary_key=True),
            sa.Column('value', sa.String(1023), nullable=False),
            mysql_engine='InnoDB',
        )
        op.add_column(
            SHARE_SERVERS_TABLE,
            sa.Column('security_service_update_support', sa.Boolean,
                      nullable=False, server_default=sa.sql.false())
        )
        op.add_column(
            SHARE_NETWORKS_TABLE,
            sa.Column('status', sa.String(36), nullable=False,
                      server_default=constants.STATUS_NETWORK_ACTIVE))
    except Exception:
        msg_args = {
            'async_op_table': ASYNC_OPERATION_DATA_TABLE,
            'sec_serv_column': 'share_servers.security_service_update_support',
            'shr_net_column': 'share_networks.status',
        }
        LOG.error('Table %(async_op_table)s and table columns '
                  '%(sec_serv_column)s and %(shr_net_column)s were not'
                  ' created!', msg_args)
        raise


def downgrade():
    try:
        op.drop_table(ASYNC_OPERATION_DATA_TABLE)
        op.drop_column(SHARE_SERVERS_TABLE, 'security_service_update_support')
        op.drop_column(SHARE_NETWORKS_TABLE, 'status')
    except Exception:
        msg_args = {
            'async_op_table': ASYNC_OPERATION_DATA_TABLE,
            'sec_serv_column': 'share_servers.security_service_update_support',
            'shr_net_column': 'share_networks.status',
        }
        LOG.error('Table %(async_op_table)s and table columns '
                  '%(sec_serv_column)s and %(shr_net_column)s were not '
                  'dropped!', msg_args)
        raise
