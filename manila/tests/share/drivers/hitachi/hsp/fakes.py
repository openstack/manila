# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

file_system = {
    'id': '33689245-1806-45d0-8507-0700b5f89750',
    'properties': {
        'cluster-id': '85d5b9e2-27f3-11e6-8b50-005056a75f66',
        'quota': 107374182400,
        'name': '07c966f9-fea2-4e12-ab72-97cb3c529bb5',
        'used-capacity': 53687091200,
        'free-capacity': 53687091200
    },
}

share = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'properties': {
        'file-system-id': '33689245-1806-45d0-8507-0700b5f89750',
        'file-system-name': 'fake_name',
    },
}

invalid_share = {
    'id': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'name': 'aa4a7710-f326-41fb-ad18-b4ad587fc87a',
    'size': 100,
    'host': 'hsp',
    'share_proto': 'CIFS',
}

access_rule = {
    'id': 'acdc7172b-fe07-46c4-b78f-df3e0324ccd0',
    'access_type': 'ip',
    'access_to': '172.24.44.200',
    'access_level': 'rw',
}

hsp_rules = [{
    'name': 'qa_access',
    'host-specification': '172.24.44.200',
    'read-write': 'true',
}]

hsp_cluster = {
    'id': '835e7c00-9d04-11e5-a935-f4521480e990',
    'properties': {
        'total-storage-capacity': 107374182400,
        'total-storage-used': 53687091200,
        'total-storage-available': 53687091200,
        'total-file-system-capacity': 107374182400,
        'total-file-system-space-used': 53687091200,
        'total-file-system-space-available': 53687091200
    },
}

stats_data = {
    'share_backend_name': 'HSP',
    'vendor_name': 'Hitachi',
    'driver_version': '1.0.0',
    'storage_protocol': 'NFS',
    'pools': [{
        'reserved_percentage': 0,
        'pool_name': 'HSP',
        'thin_provisioning': True,
        'total_capacity_gb': 100,
        'free_capacity_gb': 50,
        'max_over_subscription_ratio': 20,
        'qos': False,
        'dedupe': False,
        'compression': False,
    }],
}
