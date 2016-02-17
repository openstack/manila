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

"""Add more network info attributes to 'network_allocations' table.

Revision ID: 5155c7077f99
Revises: 293fac1130ca
Create Date: 2015-12-22 12:05:24.297049

"""

# revision identifiers, used by Alembic.
revision = '5155c7077f99'
down_revision = '293fac1130ca'

from alembic import op
import sqlalchemy as sa


def upgrade():
    default_label_value = 'user'
    op.add_column(
        'network_allocations',
        sa.Column('label',
                  sa.String(255),
                  default=default_label_value,
                  server_default=default_label_value,
                  nullable=True),
    )
    op.add_column(
        'network_allocations',
        sa.Column('network_type', sa.String(32), nullable=True))
    op.add_column(
        'network_allocations',
        sa.Column('segmentation_id', sa.Integer, nullable=True))
    op.add_column(
        'network_allocations',
        sa.Column('ip_version', sa.Integer, nullable=True))
    op.add_column(
        'network_allocations',
        sa.Column('cidr', sa.String(64), nullable=True))


def downgrade():
    for col_name in ('label', 'network_type', 'segmentation_id', 'ip_version',
                     'cidr'):
        op.drop_column('network_allocations', col_name)
