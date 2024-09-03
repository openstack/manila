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

"""add-ensuring-field-to-services

Revision ID: cdefa6287df8
Revises: 2f27d904214c
Create Date: 2024-07-15 14:29:16.733696

"""

# revision identifiers, used by Alembic.
revision = 'cdefa6287df8'
down_revision = '2f27d904214c'

from alembic import op
from oslo_log import log
import sqlalchemy as sa


LOG = log.getLogger(__name__)


def upgrade():
    try:
        op.add_column('services', sa.Column(
            'ensuring', sa.Boolean,
            nullable=False, server_default=sa.sql.false()))
    except Exception:
        LOG.error("Column services.ensuring not created!")
        raise


def downgrade():
    try:
        op.drop_column('services', 'ensuring')
    except Exception:
        LOG.error("Column shares.ensuring not dropped!")
        raise
