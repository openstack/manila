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

"""Add defaultadsite to security service

Revision ID: 636ecb8f3939
Revises: fbdfabcba377
Create Date: 2022-08-09 10:29:08.394103

"""

# revision identifiers, used by Alembic.
revision = '636ecb8f3939'
down_revision = 'fbdfabcba377'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'security_services',
        sa.Column('defaultadsite', sa.String(255), nullable=True))


def downgrade():
    op.drop_column('security_services', 'defaultadsite')
