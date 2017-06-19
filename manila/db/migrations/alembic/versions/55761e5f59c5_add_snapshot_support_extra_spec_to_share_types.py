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

"""Add 'snapshot_support' extra spec to share types

Revision ID: 55761e5f59c5
Revises: 1f0bd302c1a6
Create Date: 2015-08-13 14:02:54.656864

"""

# revision identifiers, used by Alembic.
revision = '55761e5f59c5'
down_revision = '1f0bd302c1a6'

from alembic import op
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.sql import table

from manila.common import constants


def upgrade():
    """Performs DB upgrade to support feature of making snapshots optional.

    Add 'snapshot_support' extra spec to all share types and
    attr 'snapshot_support' to Share model.
    """
    session = sa.orm.Session(bind=op.get_bind().connect())

    es_table = table(
        'share_type_extra_specs',
        sa.Column('created_at', sa.DateTime),
        sa.Column('deleted', sa.Integer),
        sa.Column('share_type_id', sa.String(length=36)),
        sa.Column('spec_key', sa.String(length=255)),
        sa.Column('spec_value', sa.String(length=255)))

    st_table = table(
        'share_types',
        sa.Column('deleted', sa.Integer),
        sa.Column('id', sa.Integer))

    # NOTE(vponomaryov): field 'deleted' is integer here.
    existing_extra_specs = (session.query(es_table).
                            filter(es_table.c.spec_key ==
                                   constants.ExtraSpecs.SNAPSHOT_SUPPORT).
                            filter(es_table.c.deleted == 0).
                            all())
    exclude_st_ids = [es.share_type_id for es in existing_extra_specs]

    # NOTE(vponomaryov): field 'deleted' is string here.
    share_types = (session.query(st_table).
                   filter(st_table.c.deleted.in_(('0', 'False', ))).
                   filter(st_table.c.id.notin_(exclude_st_ids)).
                   all())
    session.close_all()

    extra_specs = []
    now = timeutils.utcnow()
    for st in share_types:
        extra_specs.append({
            'spec_key': constants.ExtraSpecs.SNAPSHOT_SUPPORT,
            'spec_value': 'True',
            'deleted': 0,
            'created_at': now,
            'share_type_id': st.id,
        })
    if extra_specs:
        op.bulk_insert(es_table, extra_specs)

    # NOTE(vponomaryov): shares that were created before applying this
    # migration can have incorrect value because they were created without
    # consideration of driver capability to create snapshots.
    op.add_column('shares',
                  sa.Column('snapshot_support', sa.Boolean, default=True))

    connection = op.get_bind().connect()
    shares = sa.Table(
        'shares',
        sa.MetaData(),
        autoload=True,
        autoload_with=connection)

    update = shares.update().where(shares.c.deleted == 'False').values(
        snapshot_support=True)
    connection.execute(update)


def downgrade():
    """Performs DB downgrade removing support of 'optional snapshots' feature.

    Remove 'snapshot_support' extra spec from all share types and
    attr 'snapshot_support' from Share model.
    """
    connection = op.get_bind().connect()
    extra_specs = sa.Table(
        'share_type_extra_specs',
        sa.MetaData(),
        autoload=True,
        autoload_with=connection)

    update = extra_specs.update().where(
        extra_specs.c.spec_key == constants.ExtraSpecs.SNAPSHOT_SUPPORT).where(
        extra_specs.c.deleted == 0).values(
            deleted=extra_specs.c.id,
            deleted_at=timeutils.utcnow(),
    )
    connection.execute(update)

    op.drop_column('shares', 'snapshot_support')
