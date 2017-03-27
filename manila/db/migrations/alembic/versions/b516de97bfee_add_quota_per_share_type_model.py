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

"""Add ProjectShareTypeQuota model

Revision ID: b516de97bfee
Revises: 238720805ce1
Create Date: 2017-03-27 15:11:11.449617

"""

# revision identifiers, used by Alembic.
revision = 'b516de97bfee'
down_revision = '238720805ce1'

from alembic import op
import sqlalchemy as sql

NEW_TABLE_NAME = 'project_share_type_quotas'


def upgrade():
    op.create_table(
        NEW_TABLE_NAME,
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('project_id', sql.String(length=255)),
        sql.Column('resource', sql.String(length=255), nullable=False),
        sql.Column('hard_limit', sql.Integer, nullable=True),
        sql.Column('created_at', sql.DateTime),
        sql.Column('updated_at', sql.DateTime),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('deleted', sql.Integer, default=0),
        sql.Column(
            'share_type_id', sql.String(36),
            sql.ForeignKey(
                'share_types.id', name='share_type_id_fk',
            ),
            nullable=False),
        sql.UniqueConstraint(
            'share_type_id', 'resource', 'deleted',
            name="uc_quotas_per_share_types"),
        mysql_engine='InnoDB',
    )
    for table_name in ('quota_usages', 'reservations'):
        op.add_column(
            table_name,
            sql.Column('share_type_id', sql.String(36), nullable=True),
        )


def downgrade():
    op.drop_table(NEW_TABLE_NAME)
    for table_name in ('quota_usages', 'reservations'):
        op.drop_column(table_name, 'share_type_id')
