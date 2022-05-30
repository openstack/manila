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

"""add_transfers

Revision ID: 1e2d600bf972
Revises: c476aeb186ec
Create Date: 2022-05-30 16:37:18.325464

"""

# revision identifiers, used by Alembic.
revision = '1e2d600bf972'
down_revision = 'c476aeb186ec'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    context = op.get_context()
    mysql_dl = context.bind.dialect.name == 'mysql'
    datetime_type = (sa.dialects.mysql.DATETIME(fsp=6)
                     if mysql_dl else sa.DateTime)

    try:
        op.create_table(
            'transfers',
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('created_at', datetime_type),
            sa.Column('updated_at', datetime_type),
            sa.Column('deleted_at', datetime_type),
            sa.Column('deleted', sa.String(36), default='False'),
            sa.Column('resource_id', sa.String(36), nullable=False),
            sa.Column('resource_type', sa.String(255), nullable=False),
            sa.Column('display_name', sa.String(255)),
            sa.Column('salt', sa.String(255)),
            sa.Column('crypt_hash', sa.String(255)),
            sa.Column('expires_at', datetime_type),
            sa.Column('source_project_id', sa.String(255), nullable=True),
            sa.Column('destination_project_id', sa.String(255), nullable=True),
            sa.Column('accepted', sa.Boolean, default=False),
            mysql_engine='InnoDB',
            mysql_charset='utf8',
        )
    except Exception:
        LOG.error("Table |%s| not created!", 'transfers')
        raise


def downgrade():
    try:
        op.drop_table('transfers')
    except Exception:
        LOG.error("transfers table not dropped")
        raise
