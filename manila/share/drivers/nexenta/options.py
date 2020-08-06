# Copyright 2019 Nexenta by DDN, Inc.
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

"""
:mod:`nexenta.options` -- Contains configuration options for Nexenta drivers.
=============================================================================

.. automodule:: nexenta.options
"""

from oslo_config import cfg

nexenta_connection_opts = [
    cfg.ListOpt('nexenta_rest_addresses',
                help='One or more comma delimited IP addresses for management '
                     'communication with NexentaStor appliance.'),
    cfg.IntOpt('nexenta_rest_port',
               default=8443,
               help='Port to connect to Nexenta REST API server.'),
    cfg.StrOpt('nexenta_rest_protocol',
               default='auto',
               choices=['http', 'https', 'auto'],
               help='Use http or https for REST connection (default auto).'),
    cfg.BoolOpt('nexenta_use_https',
                default=True,
                help='Use HTTP secure protocol for NexentaStor '
                     'management REST API connections'),
    cfg.StrOpt('nexenta_user',
               default='admin',
               help='User name to connect to Nexenta SA.',
               required=True),
    cfg.StrOpt('nexenta_password',
               help='Password to connect to Nexenta SA.',
               required=True,
               secret=True),
    cfg.StrOpt('nexenta_volume',
               default='volume1',
               help='Volume name on NexentaStor.'),
    cfg.StrOpt('nexenta_pool',
               default='pool1',
               required=True,
               help='Pool name on NexentaStor.'),
    cfg.BoolOpt('nexenta_nfs',
                default=True,
                help='Defines whether share over NFS is enabled.'),
    cfg.BoolOpt('nexenta_ssl_cert_verify',
                default=False,
                help='Defines whether the driver should check ssl cert.'),
    cfg.FloatOpt('nexenta_rest_connect_timeout',
                 default=30,
                 help='Specifies the time limit (in seconds), within '
                      'which the connection to NexentaStor management '
                      'REST API server must be established'),
    cfg.FloatOpt('nexenta_rest_read_timeout',
                 default=300,
                 help='Specifies the time limit (in seconds), '
                      'within which NexentaStor management '
                      'REST API server must send a response'),
    cfg.FloatOpt('nexenta_rest_backoff_factor',
                 default=1,
                 help='Specifies the backoff factor to apply '
                      'between connection attempts to NexentaStor '
                      'management REST API server'),
    cfg.IntOpt('nexenta_rest_retry_count',
               default=5,
               help='Specifies the number of times to repeat NexentaStor '
                    'management REST API call in case of connection errors '
                    'and NexentaStor appliance EBUSY or ENOENT errors'),
]

nexenta_nfs_opts = [
    cfg.HostAddressOpt('nexenta_nas_host',
                       help='Data IP address of Nexenta storage appliance.',
                       required=True),
    cfg.StrOpt('nexenta_mount_point_base',
               default='$state_path/mnt',
               help='Base directory that contains NFS share mount points.'),
]

nexenta_dataset_opts = [
    cfg.StrOpt('nexenta_nfs_share',
               default='nfs_share',
               help='Parent filesystem where all the shares will be created. '
                    'This parameter is only used by NexentaStor4 driver.'),
    cfg.StrOpt('nexenta_share_name_prefix',
               help='Nexenta share name prefix.',
               default='share-'),
    cfg.StrOpt('nexenta_folder',
               default='folder',
               required=True,
               help='Parent folder on NexentaStor.'),
    cfg.StrOpt('nexenta_dataset_compression',
               default='on',
               choices=['on', 'off', 'gzip', 'gzip-1', 'gzip-2', 'gzip-3',
                        'gzip-4', 'gzip-5', 'gzip-6', 'gzip-7', 'gzip-8',
                        'gzip-9', 'lzjb', 'zle', 'lz4'],
               help='Compression value for new ZFS folders.'),
    cfg.StrOpt('nexenta_dataset_dedupe',
               default='off',
               choices=['on', 'off', 'sha256', 'verify', 'sha256, verify'],
               help='Deduplication value for new ZFS folders. '
                    'Only used by NexentaStor4 driver.'),
    cfg.BoolOpt('nexenta_thin_provisioning',
                default=True,
                help=('If True shares will not be space guaranteed and '
                      'overprovisioning will be enabled.')),
    cfg.IntOpt('nexenta_dataset_record_size',
               default=131072,
               help='Specifies a suggested block size in for files in a file '
                    'system. (bytes)'),
]
