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

"""add is_soft_deleted and scheduled_to_be_deleted_at to shares table

Revision ID: 1946cb97bb8d
Revises: fbdfabcba377
Create Date: 2021-07-14 14:41:58.615439

"""

# revision identifiers, used by Alembic.
revision = '1946cb97bb8d'
down_revision = 'fbdfabcba377'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column('shares', sa.Column(
            'is_soft_deleted', sa.Boolean,
            nullable=False, server_default=sa.sql.false()))
        op.add_column('shares', sa.Column(
            'scheduled_to_be_deleted_at', sa.DateTime))
    except Exception:
        LOG.error("Columns shares.is_soft_deleted "
                  "and/or shares.scheduled_to_be_deleted_at not created!")
        raise


def downgrade():
    try:
        op.drop_column('shares', 'is_soft_deleted')
        op.drop_column('shares', 'scheduled_to_be_deleted_at')
        LOG.warning("All shares in recycle bin will automatically be "
                    "restored, need to be manually identified and deleted "
                    "again.")
    except Exception:
        LOG.error("Column shares.is_soft_deleted and/or "
                  "shares.scheduled_to_be_deleted_at not dropped!")
        raise
