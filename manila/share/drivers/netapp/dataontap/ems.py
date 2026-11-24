# Copyright (c) 2026 NetApp, Inc.
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
"""Builds and logs the periodic EMS autosupport payloads for Manila.

event-0 carries deployment identity and enabled feature flags.
event-1 carries pool topology and per-pool capacity from the SSC cache.
Both JSON payloads are also written to Manila's share.log for easy inspection.
"""

import ipaddress
import json
import socket

from oslo_config import cfg
from oslo_log import log

from manila.common import constants
from manila.share.drivers.netapp import options as netapp_opts
from manila import version as manila_version

CONF = cfg.CONF

LOG = log.getLogger(__name__)

# Capacity/utilisation fields projected into each pool_stats entry.
_POOL_STAT_KEYS = (
    'pool_name',
    'total_capacity_gb',
    'free_capacity_gb',
    'utilization',
)

# Increment this when the event-0 or event-1 JSON schema changes.
_EMS_PAYLOAD_VERSION = '1.0'

# Configuration option names that must never appear in any EMS/ASUP payload.
# Used by _safe_config_snapshot() to filter sensitive values at runtime.
EMS_SECRET_OPTS = frozenset({
    'netapp_password',
    'netapp_login',
    'netapp_private_key_file',
    'netapp_certificate_file',
    'netapp_ca_certificate_file',
    'netapp_ssl_cert_path',
    'netapp_dns_nameservers',
    'netapp_dns_domains',
    'netapp_dns_hosts',
    'netapp_identity_auth_token_path',
})

# All registered NetApp option groups whose values may be included in the
# config_snapshot section of event-0.
_NETAPP_OPT_GROUPS = (
    netapp_opts.netapp_connection_opts,
    netapp_opts.netapp_transport_opts,
    netapp_opts.netapp_basicauth_opts,
    netapp_opts.netapp_certificateauth_opts,
    netapp_opts.netapp_provisioning_opts,
    netapp_opts.netapp_cluster_opts,
    netapp_opts.netapp_support_opts,
    netapp_opts.netapp_data_motion_opts,
    netapp_opts.netapp_backup_opts,
)


def _safe_hostname():
    """Return the node's DNS hostname, never an IP address.

    If ``socket.gethostname()`` resolves to a bare IP (e.g. on minimal
    container images), try ``socket.getfqdn()`` next.  If both are IPs,
    return the generic placeholder ``'Manila_node'`` so that no address
    information leaks into the EMS payload.
    """
    def _is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    name = socket.gethostname()
    if not _is_ip(name):
        return name or 'Manila_node'
    fqdn = socket.getfqdn()
    if not _is_ip(fqdn):
        return fqdn or 'Manila_node'
    return 'Manila_node'


def _safe_config_snapshot(config):
    """Return a sanitized snapshot of all registered NetApp driver options.

    Iterates over every option in ``_NETAPP_OPT_GROUPS`` and builds a
    ``{name: value}`` dict.  An option is excluded when its name appears in
    ``EMS_SECRET_OPTS`` **or** the oslo.config option object itself is
    marked ``secret=True``.  A final ``_sanitize_configs`` pass provides an
    additional safety net.  Options whose value is ``None``, ``''``, ``[]``
    or ``{}`` are omitted to keep the payload compact.
    """
    configs = {}
    for group in _NETAPP_OPT_GROUPS:
        for opt in group:
            if _is_excluded_config_opt(opt):
                continue
            try:
                val = config.safe_get(opt.name)
                if not _is_empty(val):
                    configs[opt.name] = val
            except Exception as exc:
                LOG.debug('EMS: failed to read config option %r: %s',
                          opt.name, exc)
    return _sanitize_configs(configs)


def _is_excluded_config_opt(opt):
    """Return True if an option must never appear in an EMS payload."""
    return opt.name in EMS_SECRET_OPTS or getattr(opt, 'secret', False)


def _sanitize_configs(configs):
    """Final safety-net: strip any EMS_SECRET_OPTS key from a config dict."""
    return {k: v for k, v in configs.items() if k not in EMS_SECRET_OPTS}


def _is_empty(value):
    """Return True for None, empty string, list, or dict."""
    return value is None or value == '' or value == [] or value == {}


def build_ems_log_message_0(library):
    config = library.configuration

    # IP version support may require a live ONTAP call; default to IPv4 only.
    try:
        ip_versions = library.get_configured_ip_versions()
    except Exception:
        ip_versions = [4]

    # QoS and aggregate encryption require cluster-level credentials.
    have_cluster_creds = bool(
        getattr(library, '_have_cluster_creds', False))

    # Net Aggregate Encryption (NAE) requires both the REST client (not ZAPI)
    # and the ONTAP cluster advertising NAE capability.
    try:
        nae_support = bool(
            not config.safe_get('netapp_use_legacy_client')
            and library._client.features.NAE_SUPPORT
        )
    except Exception:
        nae_support = False

    # Replication: both DR and readable types are offered when configured.
    replication_domain = config.safe_get('replication_domain') or None
    replication_type = (
        [constants.REPLICATION_TYPE_DR, constants.REPLICATION_TYPE_READABLE]
        if replication_domain else None
    )

    # Share/share-server-level encryption is only possible when DHSS creates
    # the vserver; single-SVM (fixed vserver) reports None.
    encryption_support = (
        None if config.safe_get('netapp_vserver') else ['share_server']
    )

    features = {
        'driver_handles_share_servers': config.driver_handles_share_servers,
        'storage_protocol': '_'.join(
            p.upper() for p in CONF.enabled_share_protocols),
        'flexgroup_pools_configured': bool(library._flexgroup_pools),
        'netapp_enable_flexgroup': bool(
            config.safe_get('netapp_enable_flexgroup') or False),
        'flexgroup_pool_only': bool(
            config.safe_get('netapp_flexgroup_pool_only') or False),
        # Permitted string values: 'host', 'driver', 'writable', or None.
        # FlexGroup volumes do not support per-snapshot consistency groups,
        # so the field is None when FlexGroup pools are configured; otherwise
        # 'host' indicates host-managed consistent snapshots are available.
        'consistent_snapshot_support': (
            None if library._flexgroup_pools else 'host'),
        'ipv4_support': 4 in ip_versions,
        'ipv6_support': 6 in ip_versions,
        # NetApp-specific NFS protocol versions enabled on the SVM
        # (nfs3, nfs4.0, nfs4.1). Only applies when DHSS=True.
        'netapp_enabled_share_protocols': (
            config.safe_get('netapp_enabled_share_protocols') or []),
        # ONTAP always supports both thin and thick provisioning and can
        # enable/disable dedupe and compression per share at any time.
        # [True, False] is the capability advertisement meaning "both modes
        # are supported", mirroring what lib_base.py reports in pool stats.
        # These are not driver config knobs.
        'thin_provisioning': [True, False],
        'dedupe': [True, False],
        'compression': [True, False],
        'qos_support': have_cluster_creds,
        'qos_type_support': have_cluster_creds,
        'netapp_flexvol_encryption': getattr(
            library, '_cluster_info', {}).get('nve_support', False),
        'netapp_use_legacy_client': bool(
            config.safe_get('netapp_use_legacy_client') or False),
        'encryption_support': encryption_support,
        'netapp_aggregate_encryption_support': nae_support,
        # Transport security: whether ONTAP API traffic is encrypted and
        # how the driver authenticates to the cluster.
        'netapp_transport_type': (
            config.safe_get('netapp_transport_type') or 'http'),
        'netapp_certificate_auth': bool(
            config.safe_get('netapp_certificate_file')),
        'netapp_certificate_host_validation': bool(
            config.safe_get('netapp_certificate_host_validation') or False),
        # CIFS/SMB security hardening options.
        'netapp_cifs_aes_encryption': bool(
            config.safe_get('netapp_cifs_aes_encryption') or False),
        'netapp_cifs_smb_signing': bool(
            config.safe_get('netapp_cifs_smb_signing') or False),
        # Logical space reporting surfaces consumed-vs-physical quota data
        # to clients; useful for capacity planning telemetry.
        'netapp_enable_logical_space_reporting': bool(
            config.safe_get(
                'netapp_enable_logical_space_reporting') or False),
        # HA-aware LIF placement prevents LIF overload on partner node
        # during a failover event.
        'netapp_restrict_lif_creation_per_ha_pair': bool(
            config.safe_get(
                'netapp_restrict_lif_creation_per_ha_pair') or False),
        # Backup: True when at least one SnapVault backup type is configured.
        'backup_configured': bool(
            config.safe_get('netapp_enabled_backup_types')),
        'replication_domain': replication_domain,
        'replication_type': replication_type,
        # Replication cadence — only meaningful when replication is enabled.
        'netapp_snapmirror_schedule': (
            config.safe_get('netapp_snapmirror_schedule')
            if replication_domain else None),
    }

    payload = {
        'openstack': library._app_version,
        'driver_name': library.driver_name,
        'driver_version': manila_version.version_info.version_string(),
        'backend_name': library._backend_name,
        'features': features,
        'configs': _safe_config_snapshot(config),
    }

    LOG.debug('NetApp EMS event-0: version=%s features=%d configs=%d',
              _EMS_PAYLOAD_VERSION, len(features), len(payload['configs']))
    ems_log = _build_base(library)
    ems_log.update({
        'event-id': '0',
        'event-description': json.dumps(payload),
    })
    return ems_log


def build_ems_log_message_1(library, pool_info):
    """Build the periodic event-1 message: pool catalog with capacity stats."""
    try:
        pools_data = library._get_pools()
        pool_stats = [
            {k: pool.get(k) for k in _POOL_STAT_KEYS}
            for pool in pools_data
        ]
        pool_info.setdefault('pools', {})['pool_stats'] = pool_stats
    except Exception as exc:
        LOG.debug('EMS: could not collect pool stats for event-1: %s', exc)

    LOG.debug('NetApp EMS event-1: version=%s pools=%d',
              _EMS_PAYLOAD_VERSION,
              len(pool_info.get('pools', {}).get('pool_stats', [])))

    ems_log = _build_base(library)
    ems_log.update({
        'event-id': '1',
        'event-description': json.dumps(pool_info),
    })
    return ems_log


def _build_base(library):
    return {
        'computer-name': _safe_hostname() or 'Manila_node',
        'event-source': 'Manila driver %s' % library.driver_name,
        'app-version': library._app_version,
        'category': 'provisioning',
        'log-level': '5',
        'auto-support': 'false',
    }
