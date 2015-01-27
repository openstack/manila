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

"""add access level

Revision ID: 211836bf835c
Revises: 162a3e673105
Create Date: 2014-12-19 05:34:06.790159

"""

# revision identifiers, used by Alembic.
revision = '211836bf835c'
down_revision = '162a3e673105'

from alembic import op
import sqlalchemy as sa

from manila.common import constants


def upgrade():
    op.add_column('share_access_map',
                  sa.Column('access_level', sa.String(2),
                            default=constants.ACCESS_LEVEL_RW))


def downgrade():
    op.drop_column('share_access_map', 'access_level')
