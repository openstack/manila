# Copyright 2014 Mirantis Inc.
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

from __future__ import print_function

from oslo_config import cfg

service_option = cfg.BoolOpt("manila",
                             default=True,
                             help="Whether or not manila is expected to be "
                                  "available")

share_group = cfg.OptGroup(name="share", title="Share Service Options")

ShareGroup = [
    cfg.StrOpt("min_api_microversion",
               default="2.0",
               help="The minimum api microversion is configured to be the "
                    "value of the minimum microversion supported by Manila."),
    cfg.StrOpt("max_api_microversion",
               default="2.28",
               help="The maximum api microversion is configured to be the "
                    "value of the latest microversion supported by Manila."),
    cfg.StrOpt("region",
               default="",
               help="The share region name to use. If empty, the value "
                    "of identity.region is used instead. If no such region "
                    "is found in the service catalog, the first found one is "
                    "used."),
    cfg.StrOpt("catalog_type",
               default="share",
               help="Catalog type of the Share service."),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['public', 'admin', 'internal',
                        'publicURL', 'adminURL', 'internalURL'],
               help="The endpoint type to use for the share service."),
    cfg.BoolOpt("multitenancy_enabled",
                default=True,
                help="This option used to determine backend driver type, "
                     "multitenant driver uses share-networks, but "
                     "single-tenant doesn't."),
    cfg.BoolOpt("create_networks_when_multitenancy_enabled",
                default=True,
                help="This option is used only when other "
                     "'multitenancy_enabled' option is set to 'True'. "
                     "If this one is set to True, then tempest will create "
                     "neutron networks for each new manila share-network "
                     "it creates. Else it will use manila share-networks with "
                     "empty values (case of StandAloneNetworkPlugin and "
                     "NeutronSingleNetworkPlugin)."),
    cfg.ListOpt("enable_protocols",
                default=["nfs", "cifs"],
                help="First value of list is protocol by default, "
                     "items of list show enabled protocols at all."),
    cfg.ListOpt("enable_ip_rules_for_protocols",
                default=["nfs", "cifs", ],
                help="Selection of protocols, that should "
                     "be covered with ip rule tests"),
    cfg.ListOpt("enable_user_rules_for_protocols",
                default=[],
                help="Selection of protocols, that should "
                     "be covered with user rule tests"),
    cfg.ListOpt("enable_cert_rules_for_protocols",
                default=["glusterfs", ],
                help="Protocols that should be covered with cert rule tests."),
    cfg.ListOpt("enable_cephx_rules_for_protocols",
                default=["cephfs", ],
                help="Protocols to be covered with cephx rule tests."),
    cfg.StrOpt("username_for_user_rules",
               default="Administrator",
               help="Username, that will be used in user tests."),
    cfg.ListOpt("enable_ro_access_level_for_protocols",
                default=["nfs", ],
                help="List of protocols to run tests with ro access level."),

    # Capabilities
    cfg.StrOpt("capability_storage_protocol",
               deprecated_name="storage_protocol",
               default="NFS_CIFS",
               help="Backend protocol to target when creating volume types."),
    cfg.BoolOpt("capability_snapshot_support",
                help="Defines extra spec that satisfies specific back end "
                     "capability called 'snapshot_support' and will be used "
                     "for setting up custom share type. Defaults to value of "
                     "other config option 'run_snapshot_tests'."),
    cfg.BoolOpt("capability_create_share_from_snapshot_support",
                help="Defines extra spec that satisfies specific back end "
                     "capability called 'create_share_from_snapshot_support' "
                     "and will be used for setting up a custom share type. "
                     "Defaults to the value of run_snapshot_tests. Set it to "
                     "False if the driver being tested does not support "
                     "creating shares from snapshots."),
    cfg.BoolOpt("capability_revert_to_snapshot_support",
                help="Defines extra spec that satisfies specific back end "
                     "capability called 'revert_to_snapshot_support' "
                     "and will be used for setting up custom share type. "
                     "Defaults to the value of run_revert_to_snapshot_tests."),
    cfg.StrOpt("share_network_id",
               default="",
               help="Some backend drivers requires share network "
                    "for share creation. Share network id, that will be "
                    "used for shares. If not set, it won't be used."),
    cfg.StrOpt("alt_share_network_id",
               default="",
               help="Share network id, that will be used for shares"
                    " in alt tenant. If not set, it won't be used"),
    cfg.StrOpt("admin_share_network_id",
               default="",
               help="Share network id, that will be used for shares"
                    " in admin tenant. If not set, it won't be used"),
    cfg.BoolOpt("multi_backend",
                default=False,
                help="Runs Manila multi-backend tests."),
    cfg.ListOpt("backend_names",
                default=[],
                help="Names of share backends, that will be used with "
                     "multibackend tests. Tempest will use first two values."),
    cfg.IntOpt("share_creation_retry_number",
               default=0,
               help="Defines number of retries for share creation. "
                    "It is useful to avoid failures caused by unstable "
                    "environment."),
    cfg.IntOpt("build_interval",
               default=3,
               help="Time in seconds between share availability checks."),
    cfg.IntOpt("build_timeout",
               default=500,
               help="Timeout in seconds to wait for a share to become"
                    "available."),
    cfg.BoolOpt("suppress_errors_in_cleanup",
                default=False,
                help="Whether to suppress errors with clean up operation "
                     "or not. There are cases when we may want to skip "
                     "such errors and catch only test errors."),

    # Switching ON/OFF test suites filtered by features
    cfg.BoolOpt("run_quota_tests",
                default=True,
                help="Defines whether to run quota tests or not."),
    cfg.BoolOpt("run_extend_tests",
                default=True,
                help="Defines whether to run share extend tests or not. "
                     "Disable this feature if used driver doesn't "
                     "support it."),
    cfg.BoolOpt("run_shrink_tests",
                default=True,
                help="Defines whether to run share shrink tests or not. "
                     "Disable this feature if used driver doesn't "
                     "support it."),
    cfg.BoolOpt("run_snapshot_tests",
                default=True,
                help="Defines whether to run tests that use share snapshots "
                     "or not. Disable this feature if used driver doesn't "
                     "support it."),
    cfg.BoolOpt("run_revert_to_snapshot_tests",
                default=False,
                help="Defines whether to run tests that revert shares "
                     "to snapshots or not. Enable this feature if used "
                     "driver supports it."),
    cfg.BoolOpt("run_consistency_group_tests",
                default=True,
                help="Defines whether to run consistency group tests or not. "
                     "Disable this feature if used driver doesn't support "
                     "it."),
    cfg.BoolOpt("run_replication_tests",
                default=False,
                help="Defines whether to run replication tests or not. "
                     "Enable this feature if the driver is configured "
                     "for replication."),
    cfg.BoolOpt("run_multiple_share_replicas_tests",
                default=True,
                help="Defines whether to run multiple replicas creation test "
                     "or not. Enable this if the driver can create more than "
                     "one replica for a share."),
    cfg.BoolOpt("run_host_assisted_migration_tests",
                deprecated_name="run_migration_tests",
                default=False,
                help="Enable or disable host-assisted migration tests."),
    cfg.BoolOpt("run_driver_assisted_migration_tests",
                deprecated_name="run_migration_tests",
                default=False,
                help="Enable or disable driver-assisted migration tests."),
    cfg.BoolOpt("run_manage_unmanage_tests",
                default=False,
                help="Defines whether to run manage/unmanage tests or not. "
                     "These test may leave orphaned resources, so be careful "
                     "enabling this opt."),
    cfg.BoolOpt("run_manage_unmanage_snapshot_tests",
                default=False,
                help="Defines whether to run manage/unmanage snapshot tests "
                     "or not. These tests may leave orphaned resources, so be "
                     "careful enabling this opt."),

    cfg.StrOpt("image_with_share_tools",
               default="manila-service-image-master",
               help="Image name for vm booting with nfs/smb clients tool."),
    cfg.StrOpt("image_username",
               default="manila",
               help="Image username."),
    cfg.StrOpt("image_password",
               help="Image password. Should be used for "
                    "'image_with_share_tools' without Nova Metadata support."),
    cfg.StrOpt("client_vm_flavor_ref",
               default="100",
               help="Flavor used for client vm in scenario tests."),
    cfg.IntOpt("migration_timeout",
               default=1500,
               help="Time to wait for share migration before "
                    "timing out (seconds)."),
    cfg.StrOpt("default_share_type_name",
               help="Default share type name to use in tempest tests."),
    cfg.StrOpt("backend_replication_type",
               default='none',
               choices=['none', 'writable', 'readable', 'dr'],
               help="Specify the replication type supported by the backend."),
    cfg.IntOpt("share_size",
               default=1,
               help="Default size in GB for shares created by share tests."),
]
