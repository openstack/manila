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

"""add_access_key

Revision ID: 63809d875e32
Revises: 493eaffd79e1
Create Date: 2016-07-16 20:53:05.958896

"""

# revision identifiers, used by Alembic.
revision = '63809d875e32'
down_revision = '493eaffd79e1'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'share_access_map',
        sa.Column('access_key', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('share_access_map', 'access_key')
