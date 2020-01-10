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

"""Change the shares datetime precision for MariaDB

Revision ID: fbdfabcba377
Revises: 11ee96se625f3
Create Date: 2020-01-10 15:32:59.365323

"""

# revision identifiers, used by Alembic.
revision = 'fbdfabcba377'
down_revision = '11ee96se625f3'

from alembic import op
from sqlalchemy import DateTime, dialects


def upgrade():
    context = op.get_context()

    if context.bind.dialect.name == 'mysql':
        # override the precision of DateTime for MySQL:
        op.alter_column('shares', 'created_at',
                        existing_type=DateTime,
                        type_=dialects.mysql.DATETIME(fsp=6))
        op.alter_column('shares', 'updated_at',
                        existing_type=DateTime,
                        type_=dialects.mysql.DATETIME(fsp=6))
        op.alter_column('shares', 'deleted_at',
                        existing_type=DateTime,
                        type_=dialects.mysql.DATETIME(fsp=6))


def downgrade():
    context = op.get_context()

    if context.bind.dialect.name == 'mysql':
        # override the precision of DateTime for MySQL:
        op.alter_column('shares', 'created_at',
                        existing_type=dialects.mysql.DATETIME(fsp=6),
                        type_=DateTime)
        op.alter_column('shares', 'updated_at',
                        existing_type=dialects.mysql.DATETIME(fsp=6),
                        type_=DateTime)
        op.alter_column('shares', 'deleted_at',
                        existing_type=dialects.mysql.DATETIME(fsp=6),
                        type_=DateTime)
