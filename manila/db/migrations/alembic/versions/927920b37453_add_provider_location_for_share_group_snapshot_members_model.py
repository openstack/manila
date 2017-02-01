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

"""Add 'provider_location' attr to 'share_group_snapshot_members' model.

Revision ID: 927920b37453
Revises: a77e2ad5012d
Create Date: 2017-01-31 20:10:44.937763

"""

# revision identifiers, used by Alembic.
revision = '927920b37453'
down_revision = 'a77e2ad5012d'

from alembic import op
import sqlalchemy as sa


SGSM_TABLE_NAME = 'share_group_snapshot_members'
PROVIDER_LOCATION_NAME = 'provider_location'


def upgrade():
    op.add_column(
        SGSM_TABLE_NAME,
        sa.Column(PROVIDER_LOCATION_NAME, sa.String(255), nullable=True),
    )


def downgrade():
    op.drop_column(SGSM_TABLE_NAME, PROVIDER_LOCATION_NAME)
