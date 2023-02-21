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

"""Add share network subnet metadata

Revision ID: ac0620cbe74d
Revises: 1e2d600bf972
Create Date: 2023-01-07 14:13:25.525968

"""

# revision identifiers, used by Alembic.
revision = 'ac0620cbe74d'
down_revision = '1e2d600bf972'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

LOG = log.getLogger(__name__)

share_network_subnet_metadata_table_name = 'share_network_subnet_metadata'


def upgrade():
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sql.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sql.DateTime)
    try:
        op.create_table(
            share_network_subnet_metadata_table_name,
            sql.Column('deleted', sql.String(36), default='False'),
            sql.Column('created_at', datetime_type),
            sql.Column('updated_at', datetime_type),
            sql.Column('deleted_at', datetime_type),
            sql.Column('share_network_subnet_id', sql.String(36),
                       sql.ForeignKey('share_network_subnets.id'),
                       nullable=False),
            sql.Column('key', sql.String(255), nullable=False),
            sql.Column('value', sql.String(1023), nullable=False),
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!",
                  share_network_subnet_metadata_table_name)
        raise


def downgrade():
    try:
        op.drop_table(share_network_subnet_metadata_table_name)
    except Exception:
        LOG.error("Table |%s| not dropped!",
                  share_network_subnet_metadata_table_name)
        raise
