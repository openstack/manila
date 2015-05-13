# Copyright 2015 Hitachi Data Systems.
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

"""Add shares.task_state

Revision ID: 323840a08dc4
Revises: 3651e16d7c43
Create Date: 2015-04-30 07:58:45.175790

"""

# revision identifiers, used by Alembic.
revision = '323840a08dc4'
down_revision = '3651e16d7c43'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('shares',
                  sa.Column('task_state', sa.String(255)))


def downgrade():
    op.drop_column('shares', 'task_state')
