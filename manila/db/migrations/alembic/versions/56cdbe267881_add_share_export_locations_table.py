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
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy.sql import table


def upgrade():
    export_locations_table = op.create_table(
        'share_export_locations',
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Integer, default=0),
        sa.Column('path', sa.String(2000)),
        sa.Column('share_id', sa.String(36),
                  sa.ForeignKey('shares.id', name="sel_id_fk")),
        mysql_engine='InnoDB',
        mysql_charset='utf8')

    shares_table = table(
        'shares',
        sa.Column('created_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('deleted', sa.Integer),
        sa.Column('export_location', sa.String(length=255)),
        sa.Column('id', sa.String(length=36)),
        sa.Column('updated_at', sa.DateTime))

    export_locations = []
    session = sa.orm.Session(bind=op.get_bind().connect())
    for share in session.query(shares_table).all():
        deleted = share.deleted if isinstance(share.deleted, int) else 0
        export_locations.append({
            'created_at': share.created_at,
            'updated_at': share.updated_at,
            'deleted_at': share.deleted_at,
            'deleted': deleted,
            'share_id': share.id,
            'path': share.export_location,
        })
    op.bulk_insert(export_locations_table, export_locations)

    op.drop_column('shares', 'export_location')
    session.close_all()


def downgrade():
    """Remove share_export_locations table.

    This method can lead to data loss because only first export_location
    is saved in shares table.
    """

    op.add_column('shares',
                  sa.Column('export_location', sa.String(255)))

    export_locations_table = table(
        'share_export_locations',
        sa.Column('share_id', sa.String(length=36)),
        sa.Column('path', sa.String(length=255)),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted', sa.Integer))

    connection = op.get_bind()
    session = sa.orm.Session(bind=connection.connect())
    export_locations = session.query(
        func.min(export_locations_table.c.updated_at),
        export_locations_table.c.share_id,
        export_locations_table.c.path).filter(
            export_locations_table.c.deleted == 0).group_by(
                export_locations_table.c.share_id,
                export_locations_table.c.path).all()

    shares = sa.Table('shares', sa.MetaData(),
                      autoload=True, autoload_with=connection)

    for location in export_locations:
        update = (shares.update().where(shares.c.id == location.share_id).
                  values(export_location=location.path))
        connection.execute(update)

    op.drop_table('share_export_locations')
    session.close_all()
