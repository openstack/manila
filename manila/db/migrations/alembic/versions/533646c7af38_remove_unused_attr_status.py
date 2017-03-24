# Copyright 2015 Mirantis, Inc.
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

"""Remove unused attr status

Revision ID: 533646c7af38
Revises: 3a482171410f
Create Date: 2015-05-28 13:13:47.651353

"""

# revision identifiers, used by Alembic.
revision = '533646c7af38'
down_revision = '3a482171410f'

from alembic import op
from oslo_log import log
import sqlalchemy as sql

from manila.common import constants

LOG = log.getLogger(__name__)
COLUMN_NAME = 'status'
TABLE_NAMES = ('network_allocations', 'security_services')


def upgrade():
    for t_name in TABLE_NAMES:
        try:
            op.drop_column(t_name, COLUMN_NAME)
        except Exception:
            LOG.error("Column '%s' could not be dropped", COLUMN_NAME)
            raise


def downgrade():
    for t_name in TABLE_NAMES:
        try:
            op.add_column(
                t_name,
                sql.Column(
                    COLUMN_NAME,
                    # NOTE(vponomaryov): original type of attr was enum. But
                    # alembic is buggy with enums [1], so use string type
                    # instead. Anyway we have no reason to keep enum/constraint
                    # on specific set of possible statuses because they have
                    # not been used.
                    # [1] - https://bitbucket.org/zzzeek/alembic/
                    # issue/89/opadd_column-and-opdrop_column-should
                    sql.String(255),
                    default=constants.STATUS_NEW,
                ),
            )
        except Exception:
            LOG.error("Column '%s' could not be added", COLUMN_NAME)
            raise
