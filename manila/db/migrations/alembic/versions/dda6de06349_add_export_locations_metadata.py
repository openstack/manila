# Copyright 2015 Mirantis Inc.
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

"""Add DB support for share instance export locations metadata.

Revision ID: dda6de06349
Revises: 323840a08dc4
Create Date: 2015-11-30 13:50:15.914232

"""

# revision identifiers, used by Alembic.
revision = 'dda6de06349'
down_revision = '323840a08dc4'

from alembic import op
from oslo_log import log
from oslo_utils import uuidutils
import sqlalchemy as sa

from manila.i18n import _LE

SI_TABLE_NAME = 'share_instances'
EL_TABLE_NAME = 'share_instance_export_locations'
ELM_TABLE_NAME = 'share_instance_export_locations_metadata'
LOG = log.getLogger(__name__)


def upgrade():
    try:
        meta = sa.MetaData()
        meta.bind = op.get_bind()

        # Add new 'is_admin_only' column in export locations table that will be
        # used for hiding admin export locations from common users in API.
        op.add_column(
            EL_TABLE_NAME,
            sa.Column('is_admin_only', sa.Boolean, default=False))

        # Create new 'uuid' column as String(36) in export locations table
        # that will be used for API.
        op.add_column(
            EL_TABLE_NAME,
            sa.Column('uuid', sa.String(36), unique=True),
        )

        # Generate UUID for each existing export location.
        el_table = sa.Table(
            EL_TABLE_NAME, meta,
            sa.Column('id', sa.Integer),
            sa.Column('uuid', sa.String(36)),
            sa.Column('is_admin_only', sa.Boolean),
        )
        for record in el_table.select().execute():
            el_table.update().values(
                is_admin_only=False,
                uuid=uuidutils.generate_uuid(),
            ).where(
                el_table.c.id == record.id,
            ).execute()

        # Make new 'uuid' column in export locations table not nullable.
        op.alter_column(
            EL_TABLE_NAME,
            'uuid',
            existing_type=sa.String(length=36),
            nullable=False,
        )
    except Exception:
        LOG.error(_LE("Failed to update '%s' table!"),
                  EL_TABLE_NAME)
        raise

    try:
        op.create_table(
            ELM_TABLE_NAME,
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('created_at', sa.DateTime),
            sa.Column('updated_at', sa.DateTime),
            sa.Column('deleted_at', sa.DateTime),
            sa.Column('deleted', sa.Integer),
            sa.Column('export_location_id', sa.Integer,
                      sa.ForeignKey('%s.id' % EL_TABLE_NAME,
                                    name="elm_id_fk"), nullable=False),
            sa.Column('key', sa.String(length=255), nullable=False),
            sa.Column('value', sa.String(length=1023), nullable=False),
            sa.UniqueConstraint('export_location_id', 'key', 'deleted',
                                name="elm_el_id_uc"),
            mysql_engine='InnoDB',
        )
    except Exception:
        LOG.error(_LE("Failed to create '%s' table!"), ELM_TABLE_NAME)
        raise


def downgrade():
    try:
        op.drop_table(ELM_TABLE_NAME)
    except Exception:
        LOG.error(_LE("Failed to drop '%s' table!"), ELM_TABLE_NAME)
        raise

    try:
        op.drop_column(EL_TABLE_NAME, 'is_admin_only')
        op.drop_column(EL_TABLE_NAME, 'uuid')
    except Exception:
        LOG.error(_LE("Failed to update '%s' table!"), EL_TABLE_NAME)
        raise
