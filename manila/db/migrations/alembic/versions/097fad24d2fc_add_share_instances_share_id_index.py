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
from oslo_db.sqlalchemy import utils
from oslo_log import log as logging
from sqlalchemy import MetaData

LOG = logging.getLogger(__name__)


def downgrade():
    pass


def ensure_indexed(migrate_engine, table_name, index_name, columns):
    if utils.index_exists_on_columns(migrate_engine, table_name, columns):
        LOG.info('Skipped adding %s because an equivalent index already'
                 ' exists.', index_name)
    else:
        utils.add_index(migrate_engine, table_name, index_name, columns)


def upgrade():
    migrate_engine = op.get_bind().engine
    meta = MetaData()
    meta.bind = migrate_engine
    for table_name, indexes in INDEXES_TO_CREATE.items():
        for index_name, columns in indexes.items():
            ensure_indexed(migrate_engine, table_name, index_name, columns)


INDEXES_TO_CREATE = {
    'network_allocations': {
        'network_allocations_share_server_id_idx': (
            'share_server_id',
        ),
    },
    'reservations': {
        'reservations_usage_id_idx': (
            'usage_id',
        ),
    },
    'services': {
        'services_availability_zone_id_idx': (
            'availability_zone_id',
        ),
    },
    'share_access_map': {
        'share_access_map_share_id_idx': (
            'share_id',
        ),
    },
    'share_group_share_type_mappings': {
        'share_group_share_type_mappings_share_group_id_idx': (
            'share_group_id',
        ),
        'share_group_share_type_mappings_share_type_id_idx': (
            'share_type_id',
        ),
    },
    'share_group_snapshots': {
        'share_group_snapshots_share_group_id_idx': (
            'share_group_id',
        ),
    },
    'share_group_type_projects': {
        'share_group_type_projects_share_group_type_id_idx': (
            'share_group_type_id',
        ),
    },
    'share_group_type_share_type_mappings': {
        'share_group_type_share_type_mappings_share_group_type_id_idx': (
            'share_group_type_id',
        ),
        'share_group_type_share_type_mappings_share_type_id_idx': (
            'share_type_id',
        ),
    },
    'share_group_type_specs': {
        'share_group_type_specs_share_group_type_id_idx': (
            'share_group_type_id',
        ),
    },
    'share_groups': {
        'share_groups_share_group_type_id_idx': (
            'share_group_type_id',
        ),
        'share_groups_share_network_id_idx': (
            'share_network_id',
        ),
        'share_groups_share_server_id_idx': (
            'share_server_id',
        ),
    },
    'share_instance_access_map': {
        'share_instance_access_map_access_id_idx': (
            'access_id',
        ),
        'share_instance_access_map_share_instance_id_idx': (
            'share_instance_id',
        ),
    },
    'share_instance_export_locations': {
        'share_instance_export_locations_share_instance_id_idx': (
            'share_instance_id',
        ),
    },
    'share_instance_export_locations_metadata': {
        'share_instance_export_locations_metadata_export_location_id_idx': (
            'export_location_id',
        ),
    },
    'share_instances': {
        'share_instances_availability_zone_id_idx': (
            'availability_zone_id',
        ),
        'share_instances_share_id_idx': (
            'share_id',
        ),
        'share_instances_share_network_id_idx': (
            'share_network_id',
        ),
        'share_instances_share_server_id_idx': (
            'share_server_id',
        ),
        'share_instances_share_type_id_idx': (
            'share_type_id',
        ),
    },
    'share_metadata': {
        'share_metadata_share_id_idx': (
            'share_id',
        ),
    },
    'share_network_security_service_association': {
        'share_network_sec_service_association_security_service_id_idx': (
            'security_service_id',
        ),
        'share_network_sec_service_association_share_network_id_idx': (
            'share_network_id',
        ),
    },
    'share_server_backend_details': {
        'share_server_backend_details_share_server_id_idx': (
            'share_server_id',
        ),
    },
    'share_servers': {
        'share_servers_share_network_id_idx': (
            'share_network_id',
        ),
    },
    'share_snapshot_access_map': {
        'share_snapshot_access_map_share_snapshot_id_idx': (
            'share_snapshot_id',
        ),
    },
    'share_snapshot_instance_access_map': {
        'share_snapshot_instance_access_map_access_id_idx': (
            'access_id',
        ),
        'share_snap_inst_access_map_share_snap_instance_id_idx': (
            'share_snapshot_instance_id',
        ),
    },
    'share_snapshot_instance_export_locations': {
        'share_snap_inst_export_locations_share_snap_inst_id_idx': (
            'share_snapshot_instance_id',
        ),
    },
    'share_snapshot_instances': {
        'share_snapshot_instances_share_instance_id_idx': (
            'share_instance_id',
        ),
        'share_snapshot_instances_snapshot_id_idx': (
            'snapshot_id',
        ),
    },
    'share_snapshots': {
        'share_snapshots_share_id_idx': (
            'share_id',
        ),
    },
    'share_type_extra_specs': {
        'share_type_extra_specs_share_type_id_idx': (
            'share_type_id',
        ),
    },
    'share_type_projects': {
        'share_type_projects_share_type_id_idx': (
            'share_type_id',
        ),
    },
    'shares': {
        'shares_share_group_id_idx': (
            'share_group_id',
        ),
    },
}
