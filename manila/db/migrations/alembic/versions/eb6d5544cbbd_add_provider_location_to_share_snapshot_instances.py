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

"""add provider_location to share_snapshot_instances

Revision ID: eb6d5544cbbd
Revises: 5155c7077f99
Create Date: 2016-02-12 22:25:39.594545

"""

# revision identifiers, used by Alembic.
revision = 'eb6d5544cbbd'
down_revision = '5155c7077f99'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'share_snapshot_instances',
        sa.Column('provider_location', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('share_snapshot_instances', 'provider_location')
