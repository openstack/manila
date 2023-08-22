# Copyright 2021 NetApp, Inc.
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

ENDPOINT_MIGRATION_ACTIONS = 'svm/migrations/%(svm_migration_id)s'
ENDPOINT_MIGRATIONS = 'svm/migrations'
ENDPOINT_JOB_ACTIONS = 'cluster/jobs/%(job_uuid)s'
ENDPOINT_MIGRATION_GET_PROGRESS = '/storage/volumes/'

endpoints = {
    'system-get-version': {
        'method': 'get',
        'url': 'cluster?fields=version',
    },
    'svm-migration-start': {
        'method': 'post',
        'url': ENDPOINT_MIGRATIONS
    },
    'svm-migration-complete': {
        'method': 'patch',
        'url': ENDPOINT_MIGRATION_ACTIONS
    },
    'svm-migration-cancel': {
        'method': 'delete',
        'url': ENDPOINT_MIGRATION_ACTIONS
    },
    'svm-migration-get': {
        'method': 'get',
        'url': ENDPOINT_MIGRATION_ACTIONS
    },
    'get-job': {
        'method': 'get',
        'url': ENDPOINT_JOB_ACTIONS
    },
    'svm-migration-pause': {
        'method': 'patch',
        'url': ENDPOINT_MIGRATION_ACTIONS
    },
    'svm-migration-get-progress': {
        'method': 'get',
        'url': ENDPOINT_MIGRATION_GET_PROGRESS
    },
}
