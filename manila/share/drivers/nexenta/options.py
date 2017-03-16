# Copyright 2016 Nexenta Systems, Inc.
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
    cfg.HostAddressOpt('nexenta_host',
                       help='IP address of Nexenta storage appliance.'),
    cfg.IntOpt('nexenta_rest_port',
               default=8457,
               help='Port to connect to Nexenta REST API server.'),
    cfg.IntOpt('nexenta_retry_count',
               default=6,
               help='Number of retries for unsuccessful API calls.'),
    cfg.StrOpt('nexenta_rest_protocol',
               default='auto',
               choices=['http', 'https', 'auto'],
               help='Use http or https for REST connection (default auto).'),
    cfg.StrOpt('nexenta_user',
               default='admin',
               help='User name to connect to Nexenta SA.'),
    cfg.StrOpt('nexenta_password',
               help='Password to connect to Nexenta SA.',
               secret=True),
    cfg.StrOpt('nexenta_volume',
               default='volume1',
               help='Volume name on NexentaStor.'),
    cfg.StrOpt('nexenta_pool',
               default='pool1',
               help='Pool name on NexentaStor.'),
    cfg.BoolOpt('nexenta_nfs',
                default=True,
                help='On if share over NFS is enabled.'),
]

nexenta_nfs_opts = [
    cfg.StrOpt('nexenta_mount_point_base',
               default='$state_path/mnt',
               help='Base directory that contains NFS share mount points.'),
]

nexenta_dataset_opts = [
    cfg.StrOpt('nexenta_nfs_share',
               default='nfs_share',
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
               help='Deduplication value for new ZFS folders.'),
    cfg.BoolOpt('nexenta_thin_provisioning',
                default=True,
                help=('If True shares will not be space guaranteed and '
                      'overprovisioning will be enabled.')),
]
