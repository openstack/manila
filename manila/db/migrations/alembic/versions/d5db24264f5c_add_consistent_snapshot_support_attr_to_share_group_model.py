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

"""Add enum 'consistent_snapshot_support' attr to 'share_groups' model.

Revision ID: d5db24264f5c
Revises: 927920b37453
Create Date: 2017-02-03 15:59:31.134166

"""

# revision identifiers, used by Alembic.
revision = 'd5db24264f5c'
down_revision = '927920b37453'

from alembic import op
import sqlalchemy as sa


SG_TABLE_NAME = 'share_groups'
ATTR_NAME = 'consistent_snapshot_support'
ENUM_POOL_VALUE = 'pool'
ENUM_HOST_VALUE = 'host'


def upgrade():
    # Workaround for following alembic bug:
    # https://bitbucket.org/zzzeek/alembic/issue/89
    context = op.get_context()
    if context.bind.dialect.name == 'postgresql':
        op.execute(
            "CREATE TYPE %s AS ENUM ('%s', '%s')" % (
                ATTR_NAME, ENUM_POOL_VALUE, ENUM_HOST_VALUE))

    op.add_column(
        SG_TABLE_NAME,
        sa.Column(
            ATTR_NAME,
            sa.Enum(ENUM_POOL_VALUE, ENUM_HOST_VALUE, name=ATTR_NAME),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column(SG_TABLE_NAME, ATTR_NAME)
    context = op.get_context()
    if context.bind.dialect.name == 'postgresql':
        op.execute('DROP TYPE %s' % ATTR_NAME)
