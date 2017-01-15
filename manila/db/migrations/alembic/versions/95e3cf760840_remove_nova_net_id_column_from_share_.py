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

"""remove_nova_net_id_column_from_share_networks

Revision ID: 95e3cf760840
Revises: 3e7d62517afa
Create Date: 2016-12-13 16:11:05.191717

"""

# revision identifiers, used by Alembic.
revision = '95e3cf760840'
down_revision = '3e7d62517afa'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('share_networks', 'nova_net_id')


def downgrade():
    op.add_column(
        'share_networks',
        sa.Column('nova_net_id', sa.String(36), nullable=True))
