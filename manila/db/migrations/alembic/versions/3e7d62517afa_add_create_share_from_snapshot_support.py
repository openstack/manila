# Copyright (c) 2016 Clinton Knight.  All rights reserved.
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

"""Add 'create_share_from_snapshot_support' extra spec to share types

Revision ID: 3e7d62517afa
Revises: 48a7beae3117
Create Date: 2016-08-16 10:48:11.497499

"""

# revision identifiers, used by Alembic.
revision = '3e7d62517afa'
down_revision = '48a7beae3117'

from alembic import op
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.sql import table

from manila.common import constants


def upgrade():
    """Performs DB upgrade to add create_share_from_snapshot_support.

    Prior to this migration, the 'snapshot_support' extra spec meant two
    different things: a snapshot may be created, and a new share may be created
    from a snapshot. With the planned addition of new snapshot semantics
    (revert to snapshot, mountable snapshots), it is likely a driver may be
    able to support one or both of the new semantics but *not* be able to
    create a share from a snapshot. So this migration separates the existing
    snapshot_support extra spec and share attribute into two values to enable
    logical separability of the features.

    Add 'create_share_from_snapshot_support' extra spec to all share types and
    attribute 'create_share_from_snapshot_support' to Share model.
    """
    session = sa.orm.Session(bind=op.get_bind().connect())

    extra_specs_table = table(
        'share_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('deleted', sa.Integer),
        sa.Column('share_type_id', sa.String(length=36)),
        sa.Column('spec_key', sa.String(length=255)),
        sa.Column('spec_value', sa.String(length=255)))

    share_type_table = table(
        'share_types',
        sa.Column('deleted', sa.Integer),
        sa.Column('id', sa.Integer))

    # Get list of share type IDs that don't already have the new required
    # create_share_from_snapshot_support extra spec defined.
    existing_extra_specs = session.query(
        extra_specs_table).filter(
        extra_specs_table.c.spec_key ==
        constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT).filter(
        extra_specs_table.c.deleted == 0).all()
    excluded_st_ids = [es.share_type_id for es in existing_extra_specs]

    # Get share types for the IDs we got in the previous query
    share_types = session.query(share_type_table).filter(
        share_type_table.c.deleted.in_(('0', 'False', ))).filter(
        share_type_table.c.id.notin_(excluded_st_ids)).all()

    extra_specs = []
    now = timeutils.utcnow()
    for share_type in share_types:

        # Get the value of snapshot_support for each extant share type
        snapshot_support_extra_spec = session.query(
            extra_specs_table).filter(
            extra_specs_table.c.spec_key ==
            constants.ExtraSpecs.SNAPSHOT_SUPPORT).filter(
            extra_specs_table.c.share_type_id == share_type.id).first()

        spec_value = (snapshot_support_extra_spec.spec_value if
                      snapshot_support_extra_spec else 'False')

        # Copy the snapshot_support value to create_share_from_snapshot_support
        extra_specs.append({
            'spec_key':
            constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT,
            'spec_value': spec_value,
            'deleted': 0,
            'created_at': now,
            'share_type_id': share_type.id,
        })
    if extra_specs:
        op.bulk_insert(extra_specs_table, extra_specs)

    # Add create_share_from_snapshot_support attribute to shares table
    op.add_column('shares',
                  sa.Column('create_share_from_snapshot_support',
                            sa.Boolean, default=True))

    # Copy snapshot_support to create_share_from_snapshot_support on each share
    shares_table = sa.Table(
        'shares',
        sa.MetaData(),
        sa.Column('id', sa.String(length=36)),
        sa.Column('deleted', sa.String(length=36)),
        sa.Column('snapshot_support', sa.Boolean),
        sa.Column('create_share_from_snapshot_support', sa.Boolean),
    )
    update = shares_table.update().where(
        shares_table.c.deleted == 'False').values(
        create_share_from_snapshot_support=shares_table.c.snapshot_support)
    session.execute(update)
    session.commit()

    session.close_all()


def downgrade():
    """Performs DB downgrade removing create_share_from_snapshot_support.

    Remove 'create_share_from_snapshot_support' extra spec from all share types
    and attribute 'create_share_from_snapshot_support' from Share model.
    """
    connection = op.get_bind().connect()
    deleted_at = timeutils.utcnow()
    extra_specs = sa.Table(
        'share_type_extra_specs',
        sa.MetaData(),
        autoload=True,
        autoload_with=connection)

    update = extra_specs.update().where(
        extra_specs.c.spec_key ==
        constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT).where(
        extra_specs.c.deleted == 0).values(deleted=extra_specs.c.id,
                                           deleted_at=deleted_at)
    connection.execute(update)

    op.drop_column('shares', 'create_share_from_snapshot_support')
