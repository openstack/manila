# Copyright 2015 Bob Callaway. All rights reserved.
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

"""change volume_type to share_type

Revision ID: 38e632621e5a
Revises: 162a3e673105
Create Date: 2014-10-02 09:14:03.172324

"""

# revision identifiers, used by Alembic.
revision = '38e632621e5a'
down_revision = '211836bf835c'

from alembic import op

from manila.i18n import _LI
from manila.openstack.common import log as logging

import sqlalchemy as sa

LOG = logging.getLogger(__name__)


def upgrade():
    LOG.info(_LI("Renaming column name volume_type_extra_specs.key to "
             "volume_type_extra_specs.spec_key"))
    op.alter_column("volume_type_extra_specs", "key",
                    new_column_name="spec_key",
                    type_=sa.String(length=255))

    LOG.info(_LI("Renaming column name volume_type_extra_specs.value to "
             "volume_type_extra_specs.spec_value"))
    op.alter_column("volume_type_extra_specs", "value",
                    new_column_name="spec_value",
                    type_=sa.String(length=255))

    LOG.info(_LI("Renaming column name shares.volume_type_id to "
             "shares.share_type.id"))
    op.alter_column("shares", "volume_type_id",
                    new_column_name="share_type_id",
                    type_=sa.String(length=36))

    LOG.info(_LI("Renaming volume_types table to share_types"))
    op.rename_table("volume_types", "share_types")
    op.drop_constraint('vt_name_uc', 'share_types', type_='unique')
    op.create_unique_constraint('st_name_uc', 'share_types',
                                ['name', 'deleted'])

    LOG.info(_LI("Creating share_type_extra_specs table"))
    op.create_table(
        'share_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Boolean),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('share_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id', name="st_id_fk"),
                  nullable=False),
        sa.Column('spec_key', sa.String(length=255)),
        sa.Column('spec_value', sa.String(length=255)),
        mysql_engine='InnoDB'
    )

    LOG.info(_LI("Migrating volume_type_extra_specs to "
                 "share_type_extra_specs"))
    op.execute("INSERT INTO share_type_extra_specs "
               "(created_at, updated_at, deleted_at, deleted, "
               "id, share_type_id, spec_key, spec_value) "
               "SELECT created_at, updated_at, deleted_at, deleted, "
               "id, volume_type_id, spec_key, spec_value "
               "FROM volume_type_extra_specs")

    LOG.info(_LI("Dropping volume_type_extra_specs table"))
    op.drop_table("volume_type_extra_specs")


def downgrade():
    LOG.info(_LI("Creating volume_type_extra_specs table"))
    op.create_table(
        'volume_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Boolean),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('volume_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id'), nullable=False),
        sa.Column('spec_key', sa.String(length=255)),
        sa.Column('spec_value', sa.String(length=255)),
        mysql_engine='InnoDB'
    )

    LOG.info(_LI("Migrating share_type_extra_specs to "
             "volume_type_extra_specs"))
    op.execute("INSERT INTO volume_type_extra_specs "
               "(created_at, updated_at, deleted_at, deleted, "
               "id, volume_type_id, spec_key, spec_value) "
               "SELECT created_at, updated_at, deleted_at, deleted, "
               "id, share_type_id, spec_key, spec_value "
               "FROM share_type_extra_specs")

    LOG.info(_LI("Dropping share_type_extra_specs table"))
    op.drop_table("share_type_extra_specs")

    LOG.info(_LI("Renaming share_types table to volume_types"))
    op.drop_constraint('st_name_uc', 'share_types', type_='unique')
    op.create_unique_constraint('vt_name_uc', 'share_types',
                                ['name', 'deleted'])
    op.rename_table("share_types", "volume_types")

    LOG.info(_LI("Renaming column name shares.share_type_id to "
             "shares.volume_type.id"))
    op.alter_column("shares", "share_type_id",
                    new_column_name="volume_type_id",
                    type_=sa.String(length=36))

    LOG.info(_LI("Renaming column name volume_type_extra_specs.spec_key to "
             "volume_type_extra_specs.key"))
    op.alter_column("volume_type_extra_specs", "spec_key",
                    new_column_name="key",
                    type_=sa.String(length=255))

    LOG.info(_LI("Renaming column name volume_type_extra_specs.spec_value to "
             "volume_type_extra_specs.value"))
    op.alter_column("volume_type_extra_specs", "spec_value",
                    new_column_name="value",
                    type_=sa.String(length=255))
