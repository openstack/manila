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

"""add default_ad_site to security service

Revision ID: c476aeb186ec
Revises: bb5938d74b73
Create Date: 2022-11-30 10:59:34.866946

"""

# revision identifiers, used by Alembic.
revision = 'c476aeb186ec'
down_revision = 'bb5938d74b73'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)

ss_table_name = 'security_services'


def upgrade():
    try:
        op.add_column(
            ss_table_name,
            sa.Column('default_ad_site', sa.String(255), nullable=True))
    except Exception:
        LOG.error("%s table column default_ad_site not added", ss_table_name)
        raise


def downgrade():
    try:
        op.drop_column(ss_table_name, 'default_ad_site')
    except Exception:
        LOG.error("%s table column default_ad_site not dropped", ss_table_name)
        raise
