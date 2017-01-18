# Copyright (c) 2016 Clinton Knight.  All rights reserved.
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

"""add_revert_to_snapshot_support

Revision ID: 87ce15c59bbe
Revises: 95e3cf760840
Create Date: 2016-08-18 00:12:34.587018

"""

# revision identifiers, used by Alembic.
revision = '87ce15c59bbe'
down_revision = '95e3cf760840'

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Performs DB upgrade to add revert_to_snapshot_support.

    Add attribute 'revert_to_snapshot_support' to Share model.
    """
    session = sa.orm.Session(bind=op.get_bind().connect())

    # Add create_share_from_snapshot_support attribute to shares table
    op.add_column(
        'shares',
        sa.Column('revert_to_snapshot_support', sa.Boolean, default=False))

    # Set revert_to_snapshot_support on each share
    shares_table = sa.Table(
        'shares',
        sa.MetaData(),
        sa.Column('id', sa.String(length=36)),
        sa.Column('deleted', sa.String(length=36)),
        sa.Column('revert_to_snapshot_support', sa.Boolean),
    )
    update = shares_table.update().where(
        shares_table.c.deleted == 'False').values(
            revert_to_snapshot_support=False)
    session.execute(update)
    session.commit()

    session.close_all()


def downgrade():
    """Performs DB downgrade removing revert_to_snapshot_support.

    Remove attribute 'revert_to_snapshot_support' from Share model.
    """

    op.drop_column('shares', 'revert_to_snapshot_support')
