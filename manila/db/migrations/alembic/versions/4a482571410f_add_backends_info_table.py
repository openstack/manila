# Copyright 2017 Huawei inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""add_backend_info_table

Revision ID: 4a482571410f
Revises: 27cb96d991fa
Create Date: 2017-05-18 14:47:38.201658

"""

# revision identifiers, used by Alembic.
revision = '4a482571410f'
down_revision = '27cb96d991fa'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

LOG = log.getLogger(__name__)

backend_info_table_name = 'backend_info'


def upgrade():
    try:
        op.create_table(
            backend_info_table_name,
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('deleted', sql.Integer, default=0),
            sql.Column('host', sql.String(255),
                       nullable=False, primary_key=True),
            sql.Column('info_hash', sql.String(255),
                       nullable=False),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error("Table |%s| not created!",
                  backend_info_table_name)
        raise


def downgrade():
    try:
        op.drop_table(backend_info_table_name)
    except Exception:
        LOG.error("%s table not dropped", backend_info_table_name)
        raise
