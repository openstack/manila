# Copyright 2016 SAP SE
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

"""change_user_id_length

Revision ID: 221a83cfd85b
Revises: eb6d5544cbbd
Create Date: 2016-06-21 14:22:48.314501

"""

# revision identifiers, used by Alembic.
revision = '221a83cfd85b'
down_revision = 'eb6d5544cbbd'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)


def upgrade():
    LOG.info("Changing user_id length for share_networks")
    op.alter_column("share_networks", "user_id",
                    type_=sa.String(length=255))

    LOG.info("Changing project_id length for share_networks")
    op.alter_column("share_networks", "project_id",
                    type_=sa.String(length=255))

    LOG.info("Changing project_id length for security_services")
    op.alter_column("security_services", "project_id",
                    type_=sa.String(length=255))


def downgrade():
    LOG.info("Changing back user_id length for share_networks")
    op.alter_column("share_networks", "user_id",
                    type_=sa.String(length=36))

    LOG.info("Changing back project_id length for share_networks")
    op.alter_column("share_networks", "project_id",
                    type_=sa.String(length=36))

    LOG.info("Changing back project_id length for security_services")
    op.alter_column("security_services", "project_id",
                    type_=sa.String(length=36))
