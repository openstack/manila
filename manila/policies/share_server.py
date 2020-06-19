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

from oslo_policy import policy

from manila.policies import base


BASE_POLICY_NAME = 'share_server:%s'


share_server_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'index',
        check_str=base.RULE_ADMIN_API,
        description="Get share servers.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers',
            },
            {
                'method': 'GET',
                'path': '/share-servers?{query}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'show',
        check_str=base.RULE_ADMIN_API,
        description="Show share server.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers/{server_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'details',
        check_str=base.RULE_ADMIN_API,
        description="Get share server details.",
        operations=[
            {
                'method': 'GET',
                'path': '/share-servers/{server_id}/details',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_ADMIN_API,
        description="Delete share server.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/share-servers/{server_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage_share_server',
        check_str=base.RULE_ADMIN_API,
        description="Manage share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/manage'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage_share_server',
        check_str=base.RULE_ADMIN_API,
        description="Unmanage share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description="Reset the status of a share server.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action'
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_start',
        check_str=base.RULE_ADMIN_API,
        description="Migrates a share server to the specified host.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_check',
        check_str=base.RULE_ADMIN_API,
        description="Check if can migrates a share server to the specified "
                    "host.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_complete',
        check_str=base.RULE_ADMIN_API,
        description="Invokes the 2nd phase of share server migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_cancel',
        check_str=base.RULE_ADMIN_API,
        description="Attempts to cancel share server migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_migration_get_progress',
        check_str=base.RULE_ADMIN_API,
        description=("Retrieves the share server migration progress for a "
                     "given share server."),
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'share_server_reset_task_state',
        check_str=base.RULE_ADMIN_API,
        description=("Resets task state."),
        operations=[
            {
                'method': 'POST',
                'path': '/share-servers/{share_server_id}/action',
            }
        ]),
]


def list_rules():
    return share_server_policies
