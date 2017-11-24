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


BASE_POLICY_NAME = 'share:%s'


shares_policies = [
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create',
        check_str="",
        description="Create share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get',
        check_str=base.RULE_DEFAULT,
        description="Get share.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_all',
        check_str=base.RULE_DEFAULT,
        description="List shares.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares',
            },
            {
                'method': 'GET',
                'path': '/shares/detail',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update',
        check_str=base.RULE_DEFAULT,
        description="Update share.",
        operations=[
            {
                'method': 'PUT',
                'path': '/shares',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete',
        check_str=base.RULE_DEFAULT,
        description="Delete share.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'force_delete',
        check_str=base.RULE_ADMIN_API,
        description="Force Delete a share.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'manage',
        check_str=base.RULE_ADMIN_API,
        description="Manage share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/manage',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'unmanage',
        check_str=base.RULE_ADMIN_API,
        description="Unmanage share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/unmanage',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'create_snapshot',
        check_str=base.RULE_DEFAULT,
        description="Create share snapshot.",
        operations=[
            {
                'method': 'POST',
                'path': '/snapshots',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_by_host',
        check_str=base.RULE_ADMIN_API,
        description="List share by host.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares',
            },
            {
                'method': 'GET',
                'path': '/shares/detail',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'list_by_share_server_id',
        check_str=base.RULE_ADMIN_API,
        description="List share by server id.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares'
            },
            {
                'method': 'GET',
                'path': '/shares/detail',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_get',
        check_str=base.RULE_DEFAULT,
        description="Get share access rule, it under deny access operation.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'access_get_all',
        check_str=base.RULE_DEFAULT,
        description="List share access rules.",
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'extend',
        check_str=base.RULE_DEFAULT,
        description="Extend share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'shrink',
        check_str=base.RULE_DEFAULT,
        description="Shrink share.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_start',
        check_str=base.RULE_ADMIN_API,
        description="Migrate a share to the specified host.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_complete',
        check_str=base.RULE_ADMIN_API,
        description="Invokes 2nd phase of share migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_cancel',
        check_str=base.RULE_ADMIN_API,
        description="Attempts to cancel share migration.",
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'migration_get_progress',
        check_str=base.RULE_ADMIN_API,
        description=("Retrieve share migration progress for a given "
                     "share."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_task_state',
        check_str=base.RULE_ADMIN_API,
        description=("Reset task state."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'reset_status',
        check_str=base.RULE_ADMIN_API,
        description=("Reset status."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'revert_to_snapshot',
        check_str=base.RULE_DEFAULT,
        description=("Revert a share to a snapshot."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'allow_access',
        check_str=base.RULE_DEFAULT,
        description=("Add share access rule."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'deny_access',
        check_str=base.RULE_DEFAULT,
        description=("Remove share access rule."),
        operations=[
            {
                'method': 'POST',
                'path': '/shares/{share_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_snapshot',
        check_str=base.RULE_DEFAULT,
        description=("Delete share snapshot."),
        operations=[
            {
                'method': 'DELETE',
                'path': '/snapshots/{snapshot_id}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'snapshot_update',
        check_str=base.RULE_DEFAULT,
        description=("Update share snapshot."),
        operations=[
            {
                'method': 'PUT',
                'path': '/snapshots/{snapshot_id}/action',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'update_share_metadata',
        check_str=base.RULE_DEFAULT,
        description=("Update share metadata."),
        operations=[
            {
                'method': 'PUT',
                'path': '/shares/{share_id}/metadata',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'delete_share_metadata',
        check_str=base.RULE_DEFAULT,
        description=("Delete share metadata."),
        operations=[
            {
                'method': 'DELETE',
                'path': '/shares/{share_id}/metadata/{key}',
            }
        ]),
    policy.DocumentedRuleDefault(
        name=BASE_POLICY_NAME % 'get_share_metadata',
        check_str=base.RULE_DEFAULT,
        description=("Get share metadata."),
        operations=[
            {
                'method': 'GET',
                'path': '/shares/{share_id}/metadata',
            }
        ]),
]


def list_rules():
    return shares_policies
