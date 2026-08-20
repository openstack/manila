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

"""add snapshot_inherit_share_access_support to shares

Revision ID: afc3b5e1f406
Revises: 004e506e922e
Create Date: 2026-05-19 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'afc3b5e1f406'
down_revision = '004e506e922e'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column('shares',
                      sa.Column('snapshot_inherit_share_access_support',
                                sa.Boolean, nullable=False,
                                server_default=sa.sql.false()))
    except Exception:
        LOG.error("Column shares.snapshot_inherit_share_access_support"
                  " not created!")
        raise


def downgrade():
    try:
        op.drop_column('shares', 'snapshot_inherit_share_access_support')
    except Exception:
        LOG.error("Column shares.snapshot_inherit_share_access_support"
                  " not dropped!")
        raise
