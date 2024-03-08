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

"""add mount_point_name to share_instances

Revision ID: 6e32091979e0
Revises: 99d328f0a3d2
Create Date: 2024-01-26 22:08:22.412974
"""
# revision identifiers, used by Alembic.
revision = '6e32091979e0'
down_revision = '99d328f0a3d2'

from alembic import op
from oslo_log import log
import sqlalchemy as sa

LOG = log.getLogger(__name__)
share_instances_table_name = 'share_instances'
column_name = "mount_point_name"


def upgrade():
    try:
        op.add_column(share_instances_table_name, sa.Column(column_name,
                                                            sa.String(255),
                                                            nullable=True))
    except Exception:
        LOG.error("Column mount_point_name not created!")
        raise


def downgrade():
    try:
        op.drop_column(share_instances_table_name, column_name)
    except Exception:
        LOG.error("Column mount_point_name not dropped!")
        raise
