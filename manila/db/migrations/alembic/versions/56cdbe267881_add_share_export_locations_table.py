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

"""Add share_export_locations table

Revision ID: 56cdbe267881
Revises: 17115072e1c3
Create Date: 2015-02-27 14:06:30.464315

"""

# revision identifiers, used by Alembic.
revision = '56cdbe267881'
down_revision = '30cb96d995fa'

from alembic import op
import sqlalchemy as sql


def upgrade():
    op.create_table(
        'share_export_locations',
        sql.Column('id', sql.Integer, primary_key=True, nullable=False),
        sql.Column('created_at', sql.DateTime),
        sql.Column('updated_at', sql.DateTime),
        sql.Column('deleted_at', sql.DateTime),
        sql.Column('deleted', sql.Integer, default=0),
        sql.Column('path', sql.String(2000)),
        sql.Column('share_id', sql.String(36),
                   sql.ForeignKey('shares.id', name="sel_id_fk")),
        mysql_engine='InnoDB',
        mysql_charset='utf8'
    )

    op.execute("INSERT INTO share_export_locations "
               "(created_at, deleted, path, share_id) "
               "SELECT created_at, 0, export_location, id "
               "FROM shares")

    op.drop_column('shares', 'export_location')


def downgrade():
    """Remove share_export_locations table.

    This method can lead to data loss because only first export_location
    is saved in shares table.
    """

    op.add_column('shares',
                  sql.Column('export_location', sql.String(255)))

    connection = op.get_bind()

    export_locations = connection.execute(
        "SELECT share_id, path FROM share_export_locations sel WHERE deleted=0"
        " AND updated_at = ("
        " SELECT MIN(updated_at) FROM share_export_locations sel2 "
        " WHERE sel.share_id = sel2.share_id)")

    shares = sql.Table('shares', sql.MetaData(),
                       autoload=True, autoload_with=connection)

    for location in export_locations:
        update = shares.update().where(shares.c.id == location['share_id']). \
            values(export_location=location['path'])
        connection.execute(update)

    op.drop_table('share_export_locations')
