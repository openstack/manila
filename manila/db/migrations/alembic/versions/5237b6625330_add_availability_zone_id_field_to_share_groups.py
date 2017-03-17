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

"""Add 'availability_zone_id' field to 'share_groups' table.

Revision ID: 5237b6625330
Revises: 7d142971c4ef
Create Date: 2017-03-17 18:49:53.742325

"""

# revision identifiers, used by Alembic.
revision = '5237b6625330'
down_revision = '7d142971c4ef'

from alembic import op
import sqlalchemy as sa


SG_TABLE_NAME = 'share_groups'
ATTR_NAME = 'availability_zone_id'


def upgrade():
    op.add_column(
        SG_TABLE_NAME,
        sa.Column(
            ATTR_NAME,
            sa.String(36),
            default=None,
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column(SG_TABLE_NAME, ATTR_NAME)
