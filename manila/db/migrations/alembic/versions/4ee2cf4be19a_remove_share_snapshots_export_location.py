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

"""Remove share_snapshots.export_location

Revision ID: 4ee2cf4be19a
Revises: 17115072e1c3
Create Date: 2015-02-26 11:11:55.734663

"""

# revision identifiers, used by Alembic.
revision = '4ee2cf4be19a'
down_revision = '17115072e1c3'

from alembic import op
import sqlalchemy as sql


def upgrade():
    op.drop_column('share_snapshots', 'export_location')


def downgrade():
    op.add_column('share_snapshots',
                  sql.Column('export_location', sql.String(255)))
