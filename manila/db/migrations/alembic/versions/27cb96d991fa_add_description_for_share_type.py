# Copyright (c) 2017 Huawei Technologies Co., Ltd.
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

"""add description for share type

Revision ID: 27cb96d991fa
Revises: 829a09b0ddd4
Create Date: 2017-09-16 03:07:15.548947

"""

# revision identifiers, used by Alembic.
revision = '27cb96d991fa'
down_revision = '829a09b0ddd4'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column(
            'share_types',
            sa.Column('description', sa.String(255), nullable=True))
    except Exception:
        LOG.error("Column share_types.description not created!")
        raise


def downgrade():
    try:
        op.drop_column('share_types', 'description')
    except Exception:
        LOG.error("Column share_types.description not dropped!")
        raise
