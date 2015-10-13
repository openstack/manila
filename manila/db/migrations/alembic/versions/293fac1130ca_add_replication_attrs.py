# Copyright 2015 Goutham Pacha Ravi.
# All Rights Reserved.
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

"""Add replication attributes to Share and ShareInstance models.

Revision ID: 293fac1130ca
Revises: 344c1ac4747f
Create Date: 2015-09-10 15:45:07.273043

"""

# revision identifiers, used by Alembic.
revision = '293fac1130ca'
down_revision = '344c1ac4747f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Add replication attributes to Shares and ShareInstances."""
    op.add_column('shares', sa.Column('replication_type', sa.String(255)))
    op.add_column('share_instances',
                  sa.Column('replica_state', sa.String(255)))


def downgrade():
    """Remove replication attributes from Shares and ShareInstances."""
    op.drop_column('shares', 'replication_type')
    op.drop_column('share_instances', 'replica_state')
