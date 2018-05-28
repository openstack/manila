# Copyright 2018 Huawei Corporation.
# All Rights Reserved.
#
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

"""add metadata for access rule

Revision ID: 11ee96se625f3
Revises: 097fad24d2fc
Create Date: 2018-06-16 03:07:15.548947

"""

# revision identifiers, used by Alembic.
revision = '11ee96se625f3'
down_revision = '097fad24d2fc'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

LOG = log.getLogger(__name__)

access_metadata_table_name = 'share_access_rules_metadata'


def upgrade():
    try:
        op.create_table(
            access_metadata_table_name,
            sql.Column('created_at', sql.DateTime(timezone=False)),
            sql.Column('updated_at', sql.DateTime(timezone=False)),
            sql.Column('deleted_at', sql.DateTime(timezone=False)),
            sql.Column('deleted', sql.String(36), default='False'),
            sql.Column('access_id', sql.String(36),
                       sql.ForeignKey('share_access_map.id'), nullable=False),
            sql.Column('key', sql.String(255), nullable=False),
            sql.Column('value', sql.String(1023), nullable=False),
            sql.Column('id', sql.Integer, primary_key=True, nullable=False),
            mysql_engine='InnoDB',
            mysql_charset='utf8'
        )
    except Exception:
        LOG.error("Table |%s| not created!",
                  access_metadata_table_name)
        raise


def downgrade():
    try:
        op.drop_table(access_metadata_table_name)
    except Exception:
        LOG.error("%s table not dropped", access_metadata_table_name)
        raise
