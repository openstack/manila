# Copyright 2015 Mirantis, Inc.
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

"""Add required extra spec

Revision ID: 59eb64046740
Revises: 162a3e673105
Create Date: 2015-01-29 15:33:25.348140

"""

# revision identifiers, used by Alembic.
revision = '59eb64046740'
down_revision = '4ee2cf4be19a'

from alembic import op
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.sql import table


def upgrade():
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
    existing_required_extra_specs = session.query(es_table).\
        filter(es_table.c.spec_key == 'driver_handles_share_servers').\
        filter(es_table.c.deleted == 0).\
        all()
    exclude_st_ids = [es.share_type_id for es in existing_required_extra_specs]

    # NOTE(vponomaryov): field 'deleted' is string here.
    share_types = session.query(st_table).\
        filter(st_table.c.deleted.in_(('0', 'False', ))).\
        filter(st_table.c.id.notin_(exclude_st_ids)).\
        all()

    extra_specs = []
    for st in share_types:
        extra_specs.append({
            'spec_key': 'driver_handles_share_servers',
            'spec_value': 'True',
            'deleted': 0,
            'created_at': timeutils.utcnow(),
            'share_type_id': st.id,
        })

    op.bulk_insert(es_table, extra_specs)
    session.close_all()


def downgrade():
    """Downgrade method.

    We can't determine, which extra specs should be removed after insertion,
    that's why do nothing here.
    """
