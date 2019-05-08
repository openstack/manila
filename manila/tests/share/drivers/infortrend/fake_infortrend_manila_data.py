# Copyright (c) 2019 Infortrend Technology, Inc.
# All Rights Reserved.
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


class InfortrendManilaTestData(object):

    fake_share_id = ['4d6984fd-8572-4467-964f-24936a8c4ea2',  # NFS
                     'a7b933e6-bb77-4823-a86f-f2c3ab41a8a5']  # CIFS

    fake_id = ['iftt8862-2226-0126-7610-chengweichou',
               '987c8763-3333-4444-5555-666666666666']

    fake_share_nfs = {
        'share_id': fake_share_id[0],
        'availability_zone': 'nova',
        'terminated_at': 'datetime.datetime(2017, 5, 8, 8, 27, 25)',
        'availability_zone_id': 'fd32d76d-b5a8-4c5c-93d7-8f09fc2a8ad3',
        'updated_at': 'datetime.datetime(2017, 5, 8, 8, 27, 25)',
        'share_network_id': None,
        'export_locations': [],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': '5a0aa06e-1c57-4996-be46-b81e360e8866',
        'size': 30,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': '172.27.112.223:/share-pool-01/LV-1/' +
        fake_share_id[0],
        'display_description': None,
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': 'datetime.datetime(2017, 5, 8, 8, 23, 33)',
        'scheduled_at': 'datetime.datetime(2017, 5, 8, 8, 23, 29)',
        'status': 'deleting',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': 'compute@ift-manila#share-pool-01',
        'access_rules_status': 'active',
        'display_name': 'nfs-01',
        'name': 'share-5a0aa06e-1c57-4996-be46-b81e360e8866',
        'created_at': 'datetime.datetime(2017, 5, 8, 8, 23, 29)',
        'share_proto': 'NFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }

    fake_share_cifs = {
        'share_id': fake_share_id[1],
        'availability_zone': 'nova',
        'terminated_at': None,
        'availability_zone_id': 'fd32d76d-b5a8-4c5c-93d7-8f09fc2a8ad3',
        'updated_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'share_network_id': None,
        'export_locations': [],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': 'aac4fe64-7a9c-472a-b156-9adbb50b4d29',
        'size': 50,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': None,
        'display_description': None,
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': None,
        'scheduled_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'status': 'creating',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': 'compute@ift-manila#share-pool-01',
        'access_rules_status': 'active',
        'display_name': 'cifs-01',
        'name': 'share-aac4fe64-7a9c-472a-b156-9adbb50b4d29',
        'created_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'share_proto': 'CIFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }

    fake_share_cifs_no_host = {
        'share_id': fake_share_id[1],
        'availability_zone': 'nova',
        'terminated_at': None,
        'availability_zone_id': 'fd32d76d-b5a8-4c5c-93d7-8f09fc2a8ad3',
        'updated_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'share_network_id': None,
        'export_locations': [],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': 'aac4fe64-7a9c-472a-b156-9adbb50b4d29',
        'size': 50,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': None,
        'display_description': None,
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': None,
        'scheduled_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'status': 'creating',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': '',
        'access_rules_status': 'active',
        'display_name': 'cifs-01',
        'name': 'share-aac4fe64-7a9c-472a-b156-9adbb50b4d29',
        'created_at': 'datetime.datetime(2017, 5, 9, 2, 28, 35)',
        'share_proto': 'CIFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }

    fake_non_exist_share = {
        'share_id': fake_id[0],
        'availability_zone': 'nova',
        'terminated_at': 'datetime.datetime(2017, 5, 8, 8, 27, 25)',
        'availability_zone_id': 'fd32d76d-b5a8-4c5c-93d7-8f09fc2a8ad3',
        'updated_at': 'datetime.datetime(2017, 5, 8, 8, 27, 25)',
        'share_network_id': None,
        'export_locations': [],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': fake_id[1],
        'size': 30,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': '172.27.112.223:/share-pool-01/LV-1/' +
                           fake_id[0],
        'display_description': None,
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': 'datetime.datetime(2017, 5, 8, 8, 23, 33)',
        'scheduled_at': 'datetime.datetime(2017, 5, 8, 8, 23, 29)',
        'status': 'available',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': 'compute@ift-manila#share-pool-01',
        'access_rules_status': 'active',
        'display_name': 'nfs-01',
        'name': 'share-5a0aa06e-1c57-4996-be46-b81e360e8866',
        'created_at': 'datetime.datetime(2017, 5, 8, 8, 23, 29)',
        'share_proto': 'NFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }

    fake_access_rules_nfs = [{
        'share_id': fake_share_id[0],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 8, 41, 21)',
        'updated_at': None,
        'access_type': 'ip',
        'access_to': '172.27.1.1',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': 'fa60b50f-1428-44a2-9931-7e31f0c5b033'}, {
        'share_id': fake_share_id[0],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 8, 45, 37)',
        'updated_at': None,
        'access_type': 'ip',
        'access_to': '172.27.1.2',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '9bcdd5e6-11c7-4f8f-939c-84fa2f3334bc'
    }]

    fake_rule_ip_1 = [{
        'share_id': fake_share_id[0],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 8, 41, 21)',
        'updated_at': None,
        'access_type': 'ip',
        'access_to': '172.27.1.1',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': 'fa60b50f-1428-44a2-9931-7e31f0c5b033'
    }]

    fake_rule_ip_2 = [{
        'share_id': fake_share_id[0],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 8, 45, 37)',
        'updated_at': None,
        'access_type': 'ip',
        'access_to': '172.27.1.2',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '9bcdd5e6-11c7-4f8f-939c-84fa2f3334bc'
    }]

    fake_access_rules_cifs = [{
        'share_id': fake_share_id[1],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 9, 39, 18)',
        'updated_at': None,
        'access_type': 'user',
        'access_to': 'user02',
        'access_level': 'ro',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '6e8bc969-51c9-4bbb-8e8b-020dc5fec81e'}, {
        'share_id': fake_share_id[1],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 9, 38, 59)',
        'updated_at': None,
        'access_type': 'user',
        'access_to': 'user01',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '0cd9926d-fac4-4122-a523-538e98752e78'
    }]

    fake_rule_user01 = [{
        'share_id': fake_share_id[1],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 9, 38, 59)',
        'updated_at': None,
        'access_type': 'user',
        'access_to': 'user01',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '0cd9926d-fac4-4122-a523-538e98752e78'
    }]

    fake_rule_user02 = [{
        'share_id': fake_share_id[1],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 9, 39, 18)',
        'updated_at': None,
        'access_type': 'user',
        'access_to': 'user02',
        'access_level': 'ro',
        'instance_mappings': [],
        'deleted_at': None,
        'id': '6e8bc969-51c9-4bbb-8e8b-020dc5fec81e'
    }]

    fake_rule_user03 = [{
        'share_id': fake_id[0],
        'deleted': 'False',
        'created_at': 'datetime.datetime(2017, 5, 9, 9, 39, 18)',
        'updated_at': None,
        'access_type': 'user',
        'access_to': 'user03',
        'access_level': 'rw',
        'instance_mappings': [],
        'deleted_at': None,
        'id': fake_id[1]
    }]

    fake_share_for_manage_nfs = {
        'share_id': '419ab73c-c0fc-4e73-b56a-70756e0b6d27',
        'availability_zone': None,
        'terminated_at': None,
        'availability_zone_id': None,
        'updated_at': None,
        'share_network_id': None,
        'export_locations': [{
            'uuid': '0ebd59e4-e65e-4fda-9457-320375efd0be',
            'deleted': 0,
            'created_at': 'datetime.datetime(2017, 5, 10, 10, 0, 3)',
            'updated_at': 'datetime.datetime(2017, 5, 10, 10, 0, 3)',
            'is_admin_only': False,
            'share_instance_id': 'd3cfe195-85cf-41e6-be4f-a96f7e7db192',
            'path': '172.27.112.223:/share-pool-01/LV-1/test-folder',
            'el_metadata': {},
            'deleted_at': None,
            'id': 83
        }],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': '615ac1ed-e808-40b5-8d7b-87018c6f66eb',
        'size': None,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': '172.27.112.223:/share-pool-01/LV-1/test-folder',
        'display_description': '',
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': None,
        'scheduled_at': 'datetime.datetime(2017, 5, 10, 9, 22, 5)',
        'status': 'manage_starting',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': 'compute@ift-manila#share-pool-01',
        'access_rules_status': 'active',
        'display_name': 'test-manage',
        'name': 'share-615ac1ed-e808-40b5-8d7b-87018c6f66eb',
        'created_at': 'datetime.datetime(2017, 5, 10, 9, 22, 5)',
        'share_proto': 'NFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }

    def _get_fake_share_for_manage(self, location=''):
        return {
            'share_id': '419ab73c-c0fc-4e73-b56a-70756e0b6d27',
            'availability_zone': None,
            'terminated_at': None,
            'availability_zone_id': None,
            'updated_at': None,
            'share_network_id': None,
            'export_locations': [{
                'uuid': '0ebd59e4-e65e-4fda-9457-320375efd0be',
                'deleted': 0,
                'created_at': 'datetime.datetime(2017, 5, 10, 10, 0, 3)',
                'updated_at': 'datetime.datetime(2017, 5, 10, 10, 0, 3)',
                'is_admin_only': False,
                'share_instance_id': 'd3cfe195-85cf-41e6-be4f-a96f7e7db192',
                'path': location,
                'el_metadata': {},
                'deleted_at': None,
                'id': 83
            }],
            'share_server_id': None,
            'snapshot_id': None,
            'deleted_at': None,
            'id': '615ac1ed-e808-40b5-8d7b-87018c6f66eb',
            'size': None,
            'replica_state': None,
            'user_id': '4944594433f0405588928a4212964658',
            'export_location': location,
            'display_description': '',
            'consistency_group_id': None,
            'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
            'launched_at': None,
            'scheduled_at': 'datetime.datetime(2017, 5, 10, 9, 22, 5)',
            'status': 'manage_starting',
            'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
            'deleted': 'False',
            'host': 'compute@ift-manila#share-pool-01',
            'access_rules_status': 'active',
            'display_name': 'test-manage',
            'name': 'share-615ac1ed-e808-40b5-8d7b-87018c6f66eb',
            'created_at': 'datetime.datetime(2017, 5, 10, 9, 22, 5)',
            'share_proto': 'NFS',
            'is_public': False,
            'source_cgsnapshot_member_id': None
        }

    fake_share_for_manage_cifs = {
        'share_id': '3a1222d3-c981-490a-9390-4d560ced68eb',
        'availability_zone': None,
        'terminated_at': None,
        'availability_zone_id': None,
        'updated_at': None,
        'share_network_id': None,
        'export_locations': [{
            'uuid': '0ebd59e4-e65e-4fda-9457-320375efd0de',
            'deleted': 0,
            'created_at': 'datetime.datetime(2017, 5, 11, 10, 10, 3)',
            'updated_at': 'datetime.datetime(2017, 5, 11, 10, 10, 3)',
            'is_admin_only': False,
            'share_instance_id': 'd3cfe195-85cf-41e6-be4f-a96f7e7db192',
            'path': '\\\\172.27.113.209\\test-folder-02',
            'el_metadata': {},
            'deleted_at': None,
            'id': 87
        }],
        'share_server_id': None,
        'snapshot_id': None,
        'deleted_at': None,
        'id': 'd156baf7-5422-4c9b-8c78-ee7943d000ec',
        'size': None,
        'replica_state': None,
        'user_id': '4944594433f0405588928a4212964658',
        'export_location': '\\\\172.27.113.209\\test-folder-02',
        'display_description': '',
        'consistency_group_id': None,
        'project_id': '0e63326c50a246ac81fa1a0c8e003d5b',
        'launched_at': None,
        'scheduled_at': 'datetime.datetime(2017, 5, 11, 3, 7, 59)',
        'status': 'manage_starting',
        'share_type_id': '23d8c637-0192-47fa-b921-958f22ed772f',
        'deleted': 'False',
        'host': 'compute@ift-manila#share-pool-01',
        'access_rules_status': 'active',
        'display_name': 'test-manage-02',
        'name': 'share-d156baf7-5422-4c9b-8c78-ee7943d000ec',
        'created_at': 'datetime.datetime(2017, 5, 11, 3, 7, 59)',
        'share_proto': 'CIFS',
        'is_public': False,
        'source_cgsnapshot_member_id': None
    }
