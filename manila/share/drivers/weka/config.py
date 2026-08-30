# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""oslo.config options for the Weka Manila share driver."""

from oslo_config import cfg

weka_opts = [
    # --- Connection ---
    cfg.HostAddressOpt(
        'weka_api_server',
        help=(
            'Hostname or IP address of the Weka cluster management endpoint. '
            'Must be reachable from the Manila host on port weka_api_port.'
        ),
    ),
    cfg.HostAddressOpt(
        'weka_nfs_server',
        default=None,
        help=(
            'Hostname or IP address of the Weka NFS protocol gateway, used '
            'as the NFS server address in share export locations. '
            'If not set, weka_api_server is used. Set this when the NFS '
            'gateway has a different address than the REST API endpoint '
            '(e.g. a dedicated NFS load balancer).'
        ),
    ),
    cfg.PortOpt(
        'weka_api_port',
        default=14000,
        help=(
            'TCP port for the Weka REST API. Default is 14000.'
        ),
    ),
    cfg.BoolOpt(
        'weka_ssl_verify',
        default=True,
        help=(
            'Whether to verify the Weka cluster TLS certificate. '
            'Set to False only in test/development environments.'
        ),
    ),

    # --- Authentication ---
    cfg.StrOpt(
        'weka_username',
        default='admin',
        help='Username for Weka REST API authentication.',
    ),
    cfg.StrOpt(
        'weka_password',
        secret=True,
        help='Password for Weka REST API authentication.',
    ),
    cfg.StrOpt(
        'weka_organization',
        default='Root',
        help=(
            'Weka organization name to authenticate against. '
            'Use "Root" for the root organization. For multi-tenancy, '
            'set this to the target organization name.'
        ),
    ),

    # --- Filesystem group ---
    cfg.StrOpt(
        'weka_filesystem_group',
        default='default',
        help=(
            'Name of the Weka filesystem group used for new shares. '
            'The driver will create this group if it does not exist.'
        ),
    ),

    # --- WEKAFS per-tenant isolation ---
    # Mandatory, with no on/off switch: every WEKAFS share lives in its
    # project's own Weka organization and needs an org-scoped token to
    # mount.  These options tune how that org is named and credentialed.
    # NFS shares are unaffected.
    cfg.StrOpt(
        'weka_org_admin_secret',
        secret=True,
        help=(
            'Secret key used to derive the per-organization admin password '
            'for WEKAFS tenant isolation. The password for each project\'s '
            'Weka organization admin is derived deterministically from '
            'HMAC-SHA256(weka_org_admin_secret, project_id) (the digest '
            'is then formatted to meet Weka password complexity, so it is '
            'not the raw hex), and no per-tenant secret is stored by the '
            'driver. Required: WEKAFS '
            'isolation is always enabled and the driver will not start '
            'without this secret. Keep this value stable: rotating it '
            'invalidates the logins of existing organizations.'
        ),
    ),
    cfg.StrOpt(
        'weka_org_prefix',
        default='manila-',
        help=(
            'Prefix for Weka organization names created per Manila project. '
            'The full name is "<prefix><project_id>" with dashes stripped '
            'from the project ID (not truncated). Default is "manila-".'
        ),
    ),
    cfg.StrOpt(
        'weka_org_user',
        default='manila',
        help=(
            'Base username for the per-project Weka organization. The '
            'driver creates the org\'s internal TenantAdmin under this '
            'name (used only by the driver), plus a least-privilege '
            'Regular mount user named "<weka_org_user>-mnt" that tenants '
            'log in as to mount shares. The mount user\'s password is '
            'delivered to tenants via the WEKAFS access rule access_key. '
            'Default is "manila" (so the mount user is "manila-mnt").'
        ),
    ),
    cfg.StrOpt(
        'weka_auth_token_dir',
        default='/var/lib/manila/weka-tokens',
        help=(
            'Directory on the Manila host where the driver writes '
            'per-organization mount-token files used for its own WEKAFS '
            'mounts (snapshot copies, ensure_share). Files are created '
            'with 0600 permissions. Default is '
            '"/var/lib/manila/weka-tokens".'
        ),
    ),

    # --- WEKAFS per-share access (security policies) ---
    # A share type setting the "weka:security_policy_group"
    # extra spec gets the group's Allow policies attached at creation, so
    # only the listed CIDRs may mount it.  One policy object serves every
    # share of the type, keeping a group within the org's policy budget.
    # Without the extra spec a share uses per-share policies driven by
    # its own access rules.
    cfg.StrOpt(
        'weka_security_policy_group',
        default=None,
        help=(
            'Named WEKAFS access-policy group definitions. '
            'Semicolon-separated entries, each '
            '"<group>:<rw|ro>:<cidr[,cidr...]>", e.g. '
            '"team-a:rw:10.0.1.0/24,10.0.2.0/24; team-a:ro:10.0.9.0/24; '
            'team-b:rw:10.1.0.0/16". A WEKAFS share whose share type sets '
            'the "weka:security_policy_group" extra spec to the group '
            'name is created with the matching Allow security policies '
            'attached (read-write for rw entries, read-only for ro '
            'entries); clients outside the listed CIDRs are denied the '
            'mount, and the same policy object is reused across every '
            'share of the type. Leave unset to rely solely on per-share '
            'access rules.'
        ),
    ),

    # --- POSIX client ---
    cfg.StrOpt(
        'weka_mount_point_base',
        default='/mnt/weka',
        help=(
            'Base directory on the Manila host where WekaFS filesystems '
            'will be mounted. A subdirectory per filesystem is created '
            'beneath this path.'
        ),
    ),
    cfg.IntOpt(
        'weka_num_cores',
        default=1,
        min=1,
        max=19,
        help=(
            'Number of CPU cores to allocate to the WekaFS POSIX client '
            'on the Manila host. Higher values improve throughput for '
            'IO-intensive workloads. Default is 1.'
        ),
    ),
    cfg.StrOpt(
        'weka_net_device',
        default=None,
        help=(
            'Network interface name to use for DPDK-mode WekaFS mounts '
            '(e.g. "eth0", "ens3f0"). If not set, the kernel networking '
            'stack is used (UDP mode).'
        ),
    ),

    # --- API behaviour ---
    cfg.IntOpt(
        'weka_api_timeout',
        default=30,
        min=5,
        max=300,
        help=(
            'HTTP timeout in seconds for Weka REST API requests '
            '(applied to both connection and read). Default is 30.'
        ),
    ),
    cfg.IntOpt(
        'weka_max_api_retries',
        default=3,
        min=0,
        max=10,
        help=(
            'Maximum number of retries for transient Weka API errors '
            '(HTTP 429 / 5xx). Uses exponential back-off. Default is 3.'
        ),
    ),
    cfg.IntOpt(
        'weka_api_pool_connections',
        default=4,
        min=1,
        max=20,
        help=(
            'Number of urllib3 connection pools to keep for the Weka '
            'API session. Increase when connecting to multiple backend '
            'hosts. Default is 4.'
        ),
    ),
    cfg.IntOpt(
        'weka_api_pool_maxsize',
        default=10,
        min=1,
        max=100,
        help=(
            'Maximum number of connections to save in the urllib3 '
            'pool. Should be at least as large as the expected '
            'number of concurrent API requests. Default is 10.'
        ),
    ),

    # --- Naming ---
    cfg.StrOpt(
        'weka_share_name_prefix',
        default='manila_',
        help=(
            'Prefix prepended to Weka filesystem names created for Manila '
            'shares. The full name is "<prefix><share-uuid>". '
            'Default is "manila_".'
        ),
    ),
]
