# Copyright 2018 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""add_share_instances_share_id_index

Revision ID: 097fad24d2fc
Revises: 0274d20c560f
Create Date: 2018-06-12 10:06:50.642418

"""

# revision identifiers, used by Alembic.
revision = '097fad24d2fc'
down_revision = '0274d20c560f'

from alembic import op


INDEX_NAME = 'share_instances_share_id_idx'
TABLE_NAME = 'share_instances'


def upgrade():
    op.create_index(INDEX_NAME, TABLE_NAME, ['share_id'])


def downgrade():
    op.drop_constraint('si_share_fk', TABLE_NAME, type_='foreignkey')
    op.drop_index(INDEX_NAME, TABLE_NAME)
    op.create_foreign_key(
        'si_share_fk', TABLE_NAME, 'shares', ['share_id'], ['id'])
