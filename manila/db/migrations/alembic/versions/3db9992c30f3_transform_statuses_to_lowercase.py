# Copyright 2015 Mirantis Inc.
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

"""Transform statuses to lowercase

Revision ID: 3db9992c30f3
Revises: 533646c7af38
Create Date: 2015-05-28 19:30:35.645773

"""

# revision identifiers, used by Alembic.
revision = '3db9992c30f3'
down_revision = '533646c7af38'

from alembic import op
import sqlalchemy as sa

from manila.db.migrations import utils


def upgrade():
    # NOTE(vponomaryov): shares has some statuses as uppercase, so
    # transform them in addition to statuses of share servers.
    for table in ('shares', 'share_servers'):
        _transform_case(table, make_upper=False)


def downgrade():
    # NOTE(vponomaryov): transform share server statuses to uppercase and
    # leave share statuses as is.
    _transform_case('share_servers', make_upper=True)


def _transform_case(table_name, make_upper):
    connection = op.get_bind()
    table = utils.load_table(table_name, connection)
    case = sa.func.upper if make_upper else sa.func.lower

    for row in connection.execute(table.select()):
        op.execute(
            table.update().where(
                table.c.id == row.id
            ).values({'status': case(row.status)})
        )
