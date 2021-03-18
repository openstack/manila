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

"""Change the datetime precision for all objects (MySQL and derivatives)

Revision ID: fbdfabcba377
Revises: 478c445d8d3e
Create Date: 2020-04-20 15:32:59.365323

"""

# revision identifiers, used by Alembic.
revision = 'fbdfabcba377'
down_revision = '478c445d8d3e'

from alembic import op
from sqlalchemy import DateTime, dialects


# DB Tables that can be affected by low precision timestamps in MySQL:
TABLES = ('services', 'quotas', 'project_user_quotas', 'backend_info',
          'project_share_type_quotas', 'quota_classes', 'quota_usages',
          'reservations', 'shares', 'share_instance_export_locations',
          'share_instances', 'share_instance_export_locations_metadata',
          'share_types', 'share_type_projects', 'share_type_extra_specs',
          'share_metadata', 'share_access_map', 'share_access_rules_metadata',
          'share_instance_access_map', 'share_snapshot_instances',
          'share_snapshots', 'share_snapshot_access_map', 'share_networks',
          'share_snapshot_instance_access_map', 'share_network_subnets',
          'share_snapshot_instance_export_locations', 'security_services',
          'share_servers', 'share_server_backend_details', 'share_groups',
          'network_allocations', 'share_network_security_service_association',
          'drivers_private_data', 'availability_zones', 'share_group_types',
          'share_group_type_projects', 'share_group_type_specs', 'messages',
          'share_group_snapshots', 'share_group_type_share_type_mappings',
          'share_group_share_type_mappings')


def upgrade():
    context = op.get_context()

    if context.bind.dialect.name == 'mysql':
        # override the default precision of DateTime:
        for table in TABLES:
            op.alter_column(table, 'created_at',
                            existing_type=DateTime,
                            type_=dialects.mysql.DATETIME(fsp=6))
            op.alter_column(table, 'updated_at',
                            existing_type=DateTime,
                            type_=dialects.mysql.DATETIME(fsp=6))
            op.alter_column(table, 'deleted_at',
                            existing_type=DateTime,
                            type_=dialects.mysql.DATETIME(fsp=6))


def downgrade():
    context = op.get_context()

    if context.bind.dialect.name == 'mysql':
        for table in TABLES:
            op.alter_column(table, 'created_at',
                            existing_type=dialects.mysql.DATETIME(fsp=6),
                            type_=DateTime)
            op.alter_column(table, 'updated_at',
                            existing_type=dialects.mysql.DATETIME(fsp=6),
                            type_=DateTime)
            op.alter_column(table, 'deleted_at',
                            existing_type=dialects.mysql.DATETIME(fsp=6),
                            type_=DateTime)
