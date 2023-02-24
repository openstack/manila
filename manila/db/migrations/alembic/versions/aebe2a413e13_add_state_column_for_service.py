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

"""add state column for service

Revision ID: aebe2a413e13
Revises: ac0620cbe74d
Create Date: 2023-01-10 11:43:24.741726

"""

# revision identifiers, used by Alembic.
revision = 'aebe2a413e13'
down_revision = 'ac0620cbe74d'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column(
            'services',
            sa.Column('state', sa.String(36), nullable=True))
    except Exception:
        LOG.error("services table column state not added")
        raise


def downgrade():
    try:
        op.drop_column('services', 'state')
    except Exception:
        LOG.error("services table column state not dropped")
        raise
