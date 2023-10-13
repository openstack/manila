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

"""add_disable_reason_to_service

Revision ID: 99d328f0a3d2
Revises: 2d708a9a3ba9
Create Date: 2023-10-13 10:50:29.311032

"""

# revision identifiers, used by Alembic.
revision = '99d328f0a3d2'
down_revision = '2d708a9a3ba9'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column(
            'services', sa.Column(
                'disabled_reason', sa.String(length=255),
                nullable=True))
    except Exception:
        LOG.error("Column services.disabled_reason not created!")
        raise


def downgrade():
    try:
        op.drop_column('services', 'disabled_reason')
    except Exception:
        LOG.error("Column services.disabled_reason not dropped!")
        raise
