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
from oslo_log import log
from oslo_utils import strutils
import sqlalchemy as sa
from sqlalchemy.sql import table


LOG = log.getLogger(__name__)


def upgrade():
    LOG.info("Renaming column name shares.volume_type_id to "
             "shares.share_type.id")
    op.alter_column("shares", "volume_type_id",
                    new_column_name="share_type_id",
                    type_=sa.String(length=36))

    LOG.info("Renaming volume_types table to share_types")
    op.rename_table("volume_types", "share_types")
    op.drop_constraint('vt_name_uc', 'share_types', type_='unique')
    op.create_unique_constraint('st_name_uc', 'share_types',
                                ['name', 'deleted'])

    LOG.info("Creating share_type_extra_specs table")
    st_es = op.create_table(
        'share_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Integer),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('share_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id', name="st_id_fk"),
                  nullable=False),
        sa.Column('spec_key', sa.String(length=255)),
        sa.Column('spec_value', sa.String(length=255)),
        mysql_engine='InnoDB')

    LOG.info("Migrating volume_type_extra_specs to "
             "share_type_extra_specs")
    _copy_records(destination_table=st_es, up_migration=True)

    LOG.info("Dropping volume_type_extra_specs table")
    op.drop_table("volume_type_extra_specs")


def downgrade():
    LOG.info("Creating volume_type_extra_specs table")
    vt_es = op.create_table(
        'volume_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Boolean),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('volume_type_id', sa.String(length=36),
                  sa.ForeignKey('share_types.id'), nullable=False),
        sa.Column('key', sa.String(length=255)),
        sa.Column('value', sa.String(length=255)),
        mysql_engine='InnoDB')

    LOG.info("Migrating share_type_extra_specs to "
             "volume_type_extra_specs")
    _copy_records(destination_table=vt_es, up_migration=False)

    LOG.info("Dropping share_type_extra_specs table")
    op.drop_table("share_type_extra_specs")

    LOG.info("Renaming share_types table to volume_types")
    op.drop_constraint('st_name_uc', 'share_types', type_='unique')
    op.create_unique_constraint('vt_name_uc', 'share_types',
                                ['name', 'deleted'])
    op.rename_table("share_types", "volume_types")

    LOG.info("Renaming column name shares.share_type_id to "
             "shares.volume_type.id")
    op.alter_column("shares", "share_type_id",
                    new_column_name="volume_type_id",
                    type_=sa.String(length=36))


def _copy_records(destination_table, up_migration=True):
    old = ('volume', '')
    new = ('share', 'spec_')
    data_from, data_to = (old, new) if up_migration else (new, old)
    from_table = table(
        data_from[0] + '_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Boolean if up_migration else sa.Integer),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column(data_from[0] + '_type_id', sa.String(length=36)),
        sa.Column(data_from[1] + 'key', sa.String(length=255)),
        sa.Column(data_from[1] + 'value', sa.String(length=255)))

    extra_specs = []
    for es in op.get_bind().execute(from_table.select()):
        if up_migration:
            deleted = strutils.int_from_bool_as_string(es.deleted)
        else:
            deleted = strutils.bool_from_string(es.deleted, default=True)
        extra_specs.append({
            'created_at': es.created_at,
            'updated_at': es.updated_at,
            'deleted_at': es.deleted_at,
            'deleted': deleted,
            data_to[0] + '_type_id': getattr(es, data_from[0] + '_type_id'),
            data_to[1] + 'key': getattr(es, data_from[1] + 'key'),
            data_to[1] + 'value': getattr(es, data_from[1] + 'value'),
        })
    op.bulk_insert(destination_table, extra_specs)
