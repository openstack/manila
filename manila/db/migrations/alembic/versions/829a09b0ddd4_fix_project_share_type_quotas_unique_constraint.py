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

"""Fix 'project_share_type_quotas' unique constraint

Revision ID: 829a09b0ddd4
Revises: b516de97bfee
Create Date: 2017-10-12 20:15:51.267488

"""

# revision identifiers, used by Alembic.
revision = '829a09b0ddd4'
down_revision = 'b516de97bfee'

from alembic import op

TABLE_NAME = 'project_share_type_quotas'
UNIQUE_CONSTRAINT_NAME = 'uc_quotas_per_share_types'
ST_FK_NAME = 'share_type_id_fk'


def upgrade():
    op.drop_constraint(ST_FK_NAME, TABLE_NAME, type_='foreignkey')
    op.drop_constraint(UNIQUE_CONSTRAINT_NAME, TABLE_NAME, type_='unique')
    op.create_foreign_key(
        ST_FK_NAME, TABLE_NAME, 'share_types', ['share_type_id'], ['id'])
    op.create_unique_constraint(
        UNIQUE_CONSTRAINT_NAME, TABLE_NAME,
        ['share_type_id', 'resource', 'deleted', 'project_id'])


def downgrade():
    # NOTE(vponomaryov): no need to implement old behaviour as it was bug, and,
    # moreover, not compatible with data from upgraded version.
    pass
