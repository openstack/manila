# Copyright 2015 Mirantis inc.
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

"""add_driver_private_data_table

Revision ID: 3a482171410f
Revises: 56cdbe267881
Create Date: 2015-04-21 14:47:38.201658

"""

# revision identifiers, used by Alembic.
revision = '3a482171410f'
down_revision = '56cdbe267881'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

from manila.i18n import _LE

LOG = log.getLogger(__name__)

drivers_private_data_table_name = 'drivers_private_data'


def upgrade():
    try:
        op.create_table(
            drivers_private_data_table_name,
            sql.Column('created_at', sql.DateTime),
            sql.Column('updated_at', sql.DateTime),
            sql.Column('deleted_at', sql.DateTime),
            sql.Column('deleted', sql.Integer, default=0),
            sql.Column('host', sql.String(255),
                       nullable=False, primary_key=True),
            sql.Column('entity_uuid', sql.String(36),
                       nullable=False, primary_key=True),
            sql.Column('key', sql.String(255),
                       nullable=False, primary_key=True),
            sql.Column('value', sql.String(1023), nullable=False),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error(_LE("Table |%s| not created!"),
                  drivers_private_data_table_name)
        raise


def downgrade():
    try:
        op.drop_table(drivers_private_data_table_name)
    except Exception:
        LOG.error(_LE("%s table not dropped"), drivers_private_data_table_name)
        raise
