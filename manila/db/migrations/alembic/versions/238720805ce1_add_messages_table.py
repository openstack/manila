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

"""Add messages table

Revision ID: 238720805ce1
Revises: 31252d671ae5
Create Date: 2017-02-02 08:38:55.134095

"""

# revision identifiers, used by Alembic.
revision = '238720805ce1'
down_revision = '31252d671ae5'

from alembic import op
from oslo_log import log
from sqlalchemy import Column, DateTime
from sqlalchemy import MetaData, String, Table

LOG = log.getLogger(__name__)


def upgrade():
    meta = MetaData()
    meta.bind = op.get_bind()

    # New table
    messages = Table(
        'messages',
        meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('project_id', String(255), nullable=False),
        Column('request_id', String(255), nullable=True),
        Column('resource_type', String(255)),
        Column('resource_id', String(36), nullable=True),
        Column('action_id', String(10), nullable=False),
        Column('detail_id', String(10), nullable=True),
        Column('message_level', String(255), nullable=False),
        Column('created_at', DateTime(timezone=False)),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', String(36)),
        Column('expires_at', DateTime(timezone=False)),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    messages.create()


def downgrade():
    try:
        op.drop_table('messages')
    except Exception:
        LOG.error("messages table not dropped")
        raise
