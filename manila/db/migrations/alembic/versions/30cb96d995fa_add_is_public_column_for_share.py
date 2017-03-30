# Copyright 2015 mirantis Inc.
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

"""add public column for share

Revision ID: 30cb96d995fa
Revises: ef0c02b4366
Create Date: 2015-01-16 03:07:15.548947

"""

# revision identifiers, used by Alembic.
revision = '30cb96d995fa'
down_revision = 'ef0c02b4366'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column('shares', sa.Column('is_public', sa.Boolean,
                                          default=False))
    except Exception:
        LOG.error("Column shares.is_public not created!")
        raise


def downgrade():
    try:
        op.drop_column('shares', 'is_public')
    except Exception:
        LOG.error("Column shares.is_public not dropped!")
        raise
