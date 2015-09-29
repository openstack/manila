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

netapp_proxy_opts = [
    cfg.StrOpt('netapp_storage_family',
               default='ontap_cluster',
               help=('The storage family type used on the storage system; '
                     'valid values include ontap_cluster for using '
                     'clustered Data ONTAP.')), ]

netapp_connection_opts = [
    cfg.StrOpt('netapp_server_hostname',
               deprecated_name='netapp_nas_server_hostname',
               help='The hostname (or IP address) for the storage system.'),
    cfg.PortOpt('netapp_server_port',
                help=('The TCP port to use for communication with the storage '
                      'system or proxy server. If not specified, Data ONTAP '
                      'drivers will use 80 for HTTP and 443 for HTTPS.')), ]

netapp_transport_opts = [
    cfg.StrOpt('netapp_transport_type',
               deprecated_name='netapp_nas_transport_type',
               default='http',
               help=('The transport protocol used when communicating with '
                     'the storage system or proxy server. Valid values are '
                     'http or https.')), ]

netapp_basicauth_opts = [
    cfg.StrOpt('netapp_login',
               deprecated_name='netapp_nas_login',
               help=('Administrative user account name used to access the '
                     'storage system.')),
    cfg.StrOpt('netapp_password',
               deprecated_name='netapp_nas_password',
               help=('Password for the administrative user account '
                     'specified in the netapp_login option.'),
               secret=True), ]

netapp_provisioning_opts = [
    cfg.StrOpt('netapp_volume_name_template',
               deprecated_name='netapp_nas_volume_name_template',
               help='NetApp volume name template.',
               default='share_%(share_id)s'),
    cfg.StrOpt('netapp_vserver_name_template',
               default='os_%s',
               help='Name template to use for new Vserver.'),
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
               deprecated_name='netapp_root_volume_name',
               default='root',
               help='Root volume name.'),
    cfg.IntOpt('netapp_volume_snapshot_reserve_percent',
               min=0,
               max=90,
               default=5,
               help='The percentage of share space set aside as reserve for '
                    'snapshot usage; valid values range from 0 to 90.'), ]

netapp_cluster_opts = [
    cfg.StrOpt('netapp_vserver',
               help=('This option specifies the Storage Virtual Machine '
                     '(i.e. Vserver) name on the storage cluster on which '
                     'provisioning of file storage shares should occur. This '
                     'option should only be specified when the option '
                     'driver_handles_share_servers is set to False (i.e. the '
                     'driver is managing shares on a single pre-configured '
                     'Vserver).')), ]

netapp_support_opts = [
    cfg.StrOpt('netapp_trace_flags',
               help=('Comma-separated list of options that control which '
                     'trace info is written to the debug logs.  Values '
                     'include method and api.')), ]

netapp_replication_opts = [
    cfg.IntOpt('netapp_snapmirror_quiesce_timeout',
               min=0,
               default=3600,  # One Hour
               help='The maximum time in seconds to wait for existing '
                    'snapmirror transfers to complete before aborting when '
                    'promoting a replica.'), ]

CONF = cfg.CONF
CONF.register_opts(netapp_proxy_opts)
CONF.register_opts(netapp_connection_opts)
CONF.register_opts(netapp_transport_opts)
CONF.register_opts(netapp_basicauth_opts)
CONF.register_opts(netapp_provisioning_opts)
CONF.register_opts(netapp_support_opts)
CONF.register_opts(netapp_replication_opts)
