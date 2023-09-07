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

"""Contains configuration options for NetApp drivers.

Common place to hold configuration options for all NetApp drivers.
Options need to be grouped into granular units to be able to be reused
by different modules and classes. This does not restrict declaring options in
individual modules. If options are not re usable then can be declared in
individual modules. It is recommended to Keep options at a single
place to ensure re usability and better management of configuration options.
"""

from oslo_config import cfg
from oslo_config import types

netapp_proxy_opts = [
    cfg.StrOpt('netapp_storage_family',
               default='ontap_cluster',
               help=('The storage family type used on the storage system; '
                     'valid values include ontap_cluster for using '
                     'clustered Data ONTAP.')), ]

netapp_connection_opts = [
    cfg.HostAddressOpt('netapp_server_hostname',
                       help='The hostname (or IP address) for the storage '
                            'system.'),
    cfg.PortOpt('netapp_server_port',
                help=('The TCP port to use for communication with the storage '
                      'system or proxy server. If not specified, Data ONTAP '
                      'drivers will use 80 for HTTP and 443 for HTTPS.')),
    cfg.BoolOpt('netapp_use_legacy_client',
                default=True,
                help=('The ONTAP client used for retrieving and modifying '
                      'data on the storage. The legacy client relies mostly '
                      'on ZAPI calls, only using REST calls for SVM migrate '
                      'feature. If set to False, the new REST client is used, '
                      'which runs REST calls if supported, otherwise falls '
                      'back to the equivalent ZAPI call.')), ]

netapp_transport_opts = [
    cfg.StrOpt('netapp_transport_type',
               default='http',
               help=('The transport protocol used when communicating with '
                     'the storage system or proxy server. Valid values are '
                     'http or https.')),
    cfg.StrOpt('netapp_ssl_cert_path',
               help=("The path to a CA_BUNDLE file or directory with "
                     "certificates of trusted CA. If set to a directory, it "
                     "must have been processed using the c_rehash utility "
                     "supplied with OpenSSL. If not informed, it will use the "
                     "Mozilla's carefully curated collection of Root "
                     "Certificates for validating the trustworthiness of SSL "
                     "certificates.")), ]

netapp_basicauth_opts = [
    cfg.StrOpt('netapp_login',
               help=('Administrative user account name used to access the '
                     'storage system.')),
    cfg.StrOpt('netapp_password',
               help=('Password for the administrative user account '
                     'specified in the netapp_login option.'),
               secret=True), ]

netapp_provisioning_opts = [
    cfg.ListOpt('netapp_enabled_share_protocols',
                default=['nfs3', 'nfs4.0'],
                help='The NFS protocol versions that will be enabled. '
                     'Supported values include nfs3, nfs4.0, nfs4.1. This '
                     'option only applies when the option '
                     'driver_handles_share_servers is set to True. '),
    cfg.StrOpt('netapp_volume_name_template',
               help='NetApp volume name template.',
               default='share_%(share_id)s'),
    cfg.StrOpt('netapp_vserver_name_template',
               default='os_%s',
               help='Name template to use for new Vserver. '
                    'When using CIFS protocol make sure to not '
                    'configure characters illegal in DNS hostnames.'),
    cfg.StrOpt('netapp_qos_policy_group_name_template',
               help='NetApp QoS policy group name template.',
               default='qos_share_%(share_id)s'),
    cfg.StrOpt('netapp_port_name_search_pattern',
               default='(.*)',
               help='Pattern for overriding the selection of network ports '
                    'on which to create Vserver LIFs.'),
    cfg.StrOpt('netapp_lif_name_template',
               default='os_%(net_allocation_id)s',
               help='Logical interface (LIF) name template'),
    cfg.StrOpt('netapp_aggregate_name_search_pattern',
               default='(.*)',
               help='Pattern for searching available aggregates '
                    'for provisioning.'),
    cfg.StrOpt('netapp_root_volume_aggregate',
               help='Name of aggregate to create Vserver root volumes on. '
                    'This option only applies when the option '
                    'driver_handles_share_servers is set to True.'),
    cfg.StrOpt('netapp_root_volume',
               default='root',
               help='Root volume name.'),
    cfg.IntOpt('netapp_volume_snapshot_reserve_percent',
               min=0,
               max=90,
               default=5,
               help='The percentage of share space set aside as reserve for '
                    'snapshot usage; valid values range from 0 to 90.'),
    cfg.StrOpt('netapp_reset_snapdir_visibility',
               choices=['visible', 'hidden', 'default'],
               default="default",
               help="This option forces all existing shares to have their "
                    "snapshot directory visibility set to either 'visible' or "
                    "'hidden' during driver startup. If set to 'default', "
                    "nothing will be changed during startup. This will not "
                    "affect new shares, which will have their snapshot "
                    "directory always visible, unless toggled by the share "
                    "type extra spec 'netapp:hide_snapdir'."),
    cfg.StrOpt('netapp_snapmirror_policy_name_svm_template',
               help='NetApp SnapMirror policy name template for Storage '
                    'Virtual Machines (Vservers).',
               default='snapmirror_policy_%(share_server_id)s'),
    cfg.ListOpt('netapp_fpolicy_default_file_operations',
                help='NetApp FPolicy file operations to apply to a FPolicy '
                     'event, when not provided by the user using '
                     '"netapp:fpolicy_file_operations" extra-spec.',
                default=['create', 'write', 'rename']),
    cfg.StrOpt('netapp_fpolicy_policy_name_template',
               help='NetApp FPolicy policy name template.',
               default='fpolicy_policy_%(share_id)s'),
    cfg.StrOpt('netapp_fpolicy_event_name_template',
               help='NetApp FPolicy policy name template.',
               default='fpolicy_event_%(protocol)s_%(share_id)s'),
    cfg.IntOpt('netapp_cached_aggregates_status_lifetime',
               min=0,
               default=60,
               help='The maximum time in seconds that the cached aggregates '
                    'status will be considered valid. Trying to read the '
                    'expired cache leads to refreshing it.'),
    cfg.BoolOpt('netapp_enable_flexgroup',
                default=False,
                help='Specify if the FlexGroup pool is enabled. When it is '
                     'enabled, the driver will report a single pool '
                     'representing all aggregates (ONTAP chooses on which the '
                     'share will be allocated). If you want to Manila control '
                     'the aggregate selection, you can configure its custom '
                     'FlexGroup pools through netapp_flexgroup_pools option. '
                     'The FlexGroup placement is done either by ONTAP or '
                     'Manila, not both.'),
    cfg.MultiOpt('netapp_flexgroup_pools',
                 item_type=types.Dict(value_type=types.String()),
                 default={},
                 help="Multi opt of dict to represent the FlexGroup pools. "
                      "A FlexGroup pool is configured with its name and its "
                      "list of aggregates. Specify this option as many times "
                      "as you have FlexGroup pools. Each entry takes the "
                      "dict config form: "
                      "netapp_flexgroup_pools = "
                      "<pool_name>: <aggr_name1> <aggr_name2> .."),
    cfg.BoolOpt('netapp_flexgroup_pool_only',
                default=False,
                help='Specify if the FlexVol pools must not be reported when '
                     'the netapp_enable_flexgroup is enabled.'),
    cfg.IntOpt('netapp_flexgroup_volume_online_timeout',
               min=60,
               default=360,  # Default to six minutes
               help='Sets time in seconds to wait for a FlexGroup volume '
                    'create to complete and go online.'),
    cfg.IntOpt('netapp_flexgroup_aggregate_not_busy_timeout',
               min=60,
               default=360,  # Default to six minutes
               help='Provisioning FlexGroup share requires that all of its '
                    'aggregates to not be busy deploying another volume. So, '
                    'sets time in seconds to retry to create the FlexGroup '
                    'share.'),
    cfg.IntOpt('netapp_delete_busy_flexgroup_snapshot_timeout',
               min=60,
               default=360,  # Default to six minutes
               help='Sets time in seconds to wait for a FlexGroup snapshot '
                    'to not be busy with clones after splitting them.'),
    cfg.IntOpt('netapp_rest_operation_timeout',
               min=60,
               default=60,  # Default to one minutes
               help='Sets maximum amount of time in seconds to wait for a '
                    'synchronous ONTAP REST API operation to be completed.'),
    cfg.IntOpt('netapp_security_cert_expire_days',
               min=1,
               max=3652,
               default=365,
               help='Defines the expiration time (in days) for the '
                    'certificate created during the vserver creation.  This '
                    'option only applies when the option '
                    'driver_handles_share_servers is set to True.'),
]

netapp_cluster_opts = [
    cfg.StrOpt('netapp_vserver',
               help=('This option specifies the Storage Virtual Machine '
                     '(i.e. Vserver) name on the storage cluster on which '
                     'provisioning of file storage shares should occur. This '
                     'option should only be specified when the option '
                     'driver_handles_share_servers is set to False (i.e. the '
                     'driver is managing shares on a single pre-configured '
                     'Vserver).')),
    cfg.StrOpt('netapp_cluster_name',
               help=('This option specifies the Cluster Name on which '
                     'provisioning of file storage shares should occur. '
                     'If not set, the driver will try to discover by '
                     'API call.')), ]

netapp_support_opts = [
    cfg.StrOpt('netapp_trace_flags',
               help=('Comma-separated list of options that control which '
                     'trace info is written to the debug logs.  Values '
                     'include method and api. API logging can further be '
                     'filtered with the '
                     '``netapp_api_trace_pattern option``.')),
    cfg.StrOpt('netapp_api_trace_pattern',
               default='(.*)',
               help=('A regular expression to limit the API tracing. This '
                     'option is honored only if enabling ``api`` tracing '
                     'with the ``netapp_trace_flags`` option. By default, '
                     'all APIs will be traced.')),
]

netapp_data_motion_opts = [
    cfg.IntOpt('netapp_snapmirror_quiesce_timeout',
               min=0,
               default=3600,  # One Hour
               help='The maximum time in seconds to wait for existing '
                    'snapmirror transfers to complete before aborting when '
                    'promoting a replica.'),
    cfg.IntOpt('netapp_snapmirror_release_timeout',
               min=0,
               default=3600,  # One Hour
               help='The maximum time in seconds to wait for a snapmirror '
                    'release when breaking snapmirror relationships.'),
    cfg.StrOpt('netapp_snapmirror_schedule',
               default='hourly',  # One Hour
               help='An interval in either minutes or hours used to update '
                    'the SnapMirror relationship. Few valid values are: '
                    '5min, 10min, 30min, hourly etc. The schedule at the '
                    '"destination" host will be the one that will be '
                    'considered when creating a new replica, or promoting '
                    'a replica'),
    cfg.IntOpt('netapp_snapmirror_last_transfer_size_limit',
               min=512,
               default=1024,  # One MB
               help='This option set the last transfer size limit (in KB) '
                    'of snapmirror to decide whether replica is in sync or '
                    'out of sync.'),
    cfg.IntOpt('netapp_volume_move_cutover_timeout',
               min=0,
               default=3600,  # One Hour,
               help='The maximum time in seconds to wait for the completion '
                    'of a volume move operation after the cutover '
                    'was triggered.'),
    cfg.IntOpt('netapp_start_volume_move_timeout',
               min=0,
               default=3600,  # One Hour,
               help='The maximum time in seconds to wait for the completion '
                    'of a volume clone split operation in order to start a '
                    'volume move.'),
    cfg.IntOpt('netapp_migration_cancel_timeout',
               min=0,
               default=3600,  # One Hour,
               help='The maximum time in seconds that migration cancel '
                    'waits for all migration operations be completely '
                    'aborted.'),
    cfg.IntOpt('netapp_server_migration_state_change_timeout',
               min=0,
               default=3600,  # One hour,
               help='The maximum time in seconds that a share server '
                    'migration waits for a vserver to change its internal '
                    'states.'),
    cfg.BoolOpt('netapp_server_migration_check_capacity',
                default=True,
                help='Specify if the capacity check must be made by the '
                     'driver while performing a share server migration. '
                     'If enabled, the driver will validate if the destination '
                     'backend can hold all shares and snapshots capacities '
                     'from the source share server.'),
    cfg.IntOpt('netapp_server_migration_state_change_timeout',
               min=0,
               default=3600,  # One hour,
               help='The maximum time in seconds that a share server '
                    'migration waits for a vserver to change its internal '
                    'states.'),
    cfg.IntOpt('netapp_mount_replica_timeout',
               min=0,
               default=3600,  # One Hour
               help='The maximum time in seconds to wait for mounting '
                    'a replica.'),
]

CONF = cfg.CONF
CONF.register_opts(netapp_proxy_opts)
CONF.register_opts(netapp_connection_opts)
CONF.register_opts(netapp_transport_opts)
CONF.register_opts(netapp_basicauth_opts)
CONF.register_opts(netapp_provisioning_opts)
CONF.register_opts(netapp_support_opts)
CONF.register_opts(netapp_data_motion_opts)
