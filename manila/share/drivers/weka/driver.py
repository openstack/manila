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

"""Manila share driver for Weka storage."""

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import tempfile
import threading

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.privsep import weka as weka_privsep
from manila.share import driver
from manila.share.drivers.weka import client as weka_client
from manila.share.drivers.weka import config as weka_config
from manila.share.drivers.weka import exceptions as weka_exc
from manila.share.drivers.weka import posix as weka_posix
from manila.share.drivers.weka import utils as weka_utils
from manila.share import share_types
from manila import utils as manila_utils

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

DRIVER_VERSION = '1.0.0'

_WEKAFS_PROTO = 'WEKAFS'
_NFS_PROTO = 'NFS'
_SUPPORTED_PROTOCOLS = (_WEKAFS_PROTO, _NFS_PROTO)

_GiB = units.Gi


def _cidr_to_weka_ip(cidr_str):
    """Convert CIDR to the IP/dotted-mask form Weka v5 wants."""
    if '/' not in cidr_str:
        return cidr_str
    net = ipaddress.IPv4Network(cidr_str, strict=False)
    return '{}/{}'.format(str(net.network_address), str(net.netmask))


def _norm_weka_ip(value):
    """Reduce a rule to its network: Weka echoes back address/mask."""
    try:
        return str(ipaddress.IPv4Network(value, strict=False))
    except ValueError:
        return value


def _policy_ip(access_to):
    """Normalize access_to for a policy: CIDR prefix, not a mask."""
    if '/' in access_to:
        return str(ipaddress.IPv4Network(access_to, strict=False))
    return access_to


def _is_already_attached_error(exc):
    """True if an attach error means the policy is already attached.

    Weka answers 500, not 4xx, so _is_already_exists_error misses it.
    """
    if not isinstance(exc, weka_exc.WekaApiError):
        return False
    return 'already present' in str(exc).lower()


def _is_already_exists_error(exc):
    """True if a Weka API error means the resource already exists.

    Weka is inconsistent: 409, or 400 with "already exists" (rule) or
    "already in use" (user).  Gated on those codes so unrelated errors
    still raise.
    """
    if isinstance(exc, weka_exc.WekaConflict):
        return True
    if not isinstance(exc, weka_exc.WekaApiError):
        return False
    if exc.status_code not in (400, 409):
        return False
    msg = str(exc).lower()
    return 'already exist' in msg or 'already in use' in msg


def _is_ipv6(access_to):
    """Return True if the access_to value is an IPv6 address or network."""
    try:
        ipaddress.IPv6Network(access_to, strict=False)
        return True
    except ValueError:
        return False


@manila_utils.retry(retry_param=processutils.ProcessExecutionError,
                    interval=1, retries=6, backoff_rate=2,
                    backoff_sleep_max=10)
def _nfs_mount_with_retry(export, mount_path):
    """Mount an NFS export, retrying while the permission propagates."""
    weka_privsep.nfs_mount(export, mount_path)


class WekaShareDriver(driver.ShareDriver):
    """Manila share driver for Weka storage."""

    _is_driver_handles_share_servers = False
    # Weka access rules are IPv4-only; manila filters IPv6 rules out for
    # backends that declare this.
    ipv6_implemented = False

    # Per-tenant WEKAFS isolation, overridden from config in do_setup.
    # Isolation is not optional: every WEKAFS share is created inside its
    # project's own Weka organization.
    _org_prefix = 'manila-'
    _org_user = 'manila'
    _org_admin_secret = None
    _auth_token_dir = '/var/lib/manila/weka-tokens'
    # Shared policy groups parsed from weka_security_policy_group:
    #   {group: {'rw': [cidr, ...], 'ro': [cidr, ...]}}
    _policy_groups = {}
    _POLICY_GROUP_SPEC = 'weka:security_policy_group'

    def __init__(self, *args, **kwargs):
        """Initialise driver state; API client created in do_setup."""
        super(WekaShareDriver, self).__init__(
            False, *args, config_opts=[weka_config.weka_opts], **kwargs)
        self._client = None
        self._fs_group_uid = None
        # share_id -> {'status', 'fs_uid', 'fs_name'}, in memory only.
        self._async_copies = {}
        self._async_copies_lock = threading.Lock()
        self._nfs_server = None
        self._org_clients = {}
        self._org_lock = threading.Lock()

    def do_setup(self, context):
        """Initialise the driver: create API client, verify connectivity."""
        cfg_get = self.configuration.safe_get

        host = cfg_get('weka_api_server')
        port = cfg_get('weka_api_port')
        username = cfg_get('weka_username')
        password = cfg_get('weka_password')
        organization = cfg_get('weka_organization')
        ssl_verify = cfg_get('weka_ssl_verify')
        if ssl_verify is None:
            ssl_verify = True
        timeout = cfg_get('weka_api_timeout')
        max_retries = cfg_get('weka_max_api_retries')
        pool_connections = cfg_get('weka_api_pool_connections')
        pool_maxsize = cfg_get('weka_api_pool_maxsize')

        self._client = weka_client.WekaApiClient(
            host=host,
            username=username,
            password=password,
            organization=organization,
            port=port,
            ssl_verify=ssl_verify,
            timeout=timeout,
            max_retries=max_retries,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )
        self._client.login()

        self._org_prefix = cfg_get('weka_org_prefix')
        # The prefix names both the org and the auth-token file, so a
        # path separator would escape weka_auth_token_dir via os.path.join.
        if ('/' in self._org_prefix or '\\' in self._org_prefix
                or os.sep in self._org_prefix):
            raise weka_exc.WekaConfigurationError(
                reason=_(
                    'weka_org_prefix must not contain path separators: '
                    '%s') % self._org_prefix)
        self._org_user = cfg_get('weka_org_user')
        self._org_admin_secret = cfg_get('weka_org_admin_secret')
        self._auth_token_dir = cfg_get('weka_auth_token_dir')
        if not self._org_admin_secret:
            raise weka_exc.WekaConfigurationError(
                reason=_(
                    'weka_org_admin_secret must be set: WEKAFS shares are '
                    'always created with per-tenant organization '
                    'isolation, which derives per-org credentials from '
                    'this secret'))

        self._policy_groups = self._parse_policy_groups(
            cfg_get('weka_security_policy_group'))
        self._nfs_server = cfg_get('weka_nfs_server')

        try:
            status = self._client.get_cluster_status()
            cluster_name = status.get('name', 'unknown')
            cluster_version = status.get('release', 'unknown')
        except Exception as exc:
            LOG.warning("Could not fetch cluster status: %s", exc)
            cluster_name = 'unknown'
            cluster_version = 'unknown'

        LOG.info(
            "WekaShareDriver %s connected to cluster '%s' "
            "(Weka version %s)",
            DRIVER_VERSION, cluster_name, cluster_version,
        )

        if not self._nfs_server:
            LOG.warning(
                "weka_nfs_server not configured; "
                "create_share_from_snapshot will be unavailable "
                "for NFS shares."
            )

        group_name = cfg_get('weka_filesystem_group')
        self._ensure_filesystem_group(group_name)

    def check_for_setup_error(self):
        """Validate configuration and environment before starting."""
        required_opts = ['weka_api_server', 'weka_username', 'weka_password']
        missing = []
        for opt in required_opts:
            if not self.configuration.safe_get(opt):
                missing.append(opt)
        if missing:
            raise exception.InvalidInput(
                reason=_(
                    'Weka driver: required config options not set: %s'
                ) % ', '.join(missing)
            )

        proc_fs_file = '/proc/filesystems'
        wekafs_available = False
        try:
            with open(proc_fs_file, 'r') as fh:
                wekafs_available = 'wekafs' in fh.read()
        except IOError:
            pass

        if not wekafs_available:
            LOG.warning(
                "WekaFS kernel module not found in %s. "
                "POSIX shares will fail until 'wekafsio' module is loaded "
                "(run: modprobe wekafsio).",
                proc_fs_file,
            )

        if self._client:
            try:
                self._client.get_cluster_status()
            except weka_exc.WekaAuthError as exc:
                raise exception.ManilaException(
                    message=_(
                        'Weka driver: API authentication failed: %s') % exc)
            except Exception as exc:
                LOG.warning(
                    "Could not verify cluster status during setup: %s", exc)

    def create_share(self, context, share, share_server=None):
        """Create a Weka filesystem and return its export locations."""
        share_proto = share['share_proto'].upper()
        if share_proto not in _SUPPORTED_PROTOCOLS:
            raise exception.InvalidShare(
                reason=_(
                    'Unsupported share protocol: %s. '
                    'Supported: %s'
                ) % (share_proto, ', '.join(_SUPPORTED_PROTOCOLS))
            )

        fs_name = self._share_name(share['id'])
        size_bytes = weka_utils.gb_to_bytes(share['size'])
        group_name = self.configuration.safe_get('weka_filesystem_group')

        LOG.debug(
            "Creating share %s (protocol %s, size %s GiB) "
            "as Weka filesystem '%s'",
            share['id'], share_proto, share['size'], fs_name,
        )

        # WEKAFS shares are created auth_required inside the project's
        # own org; NFS shares stay in the admin org.
        client = self._client_for_share(share)
        auth_required = self._is_isolated_wekafs(share)

        fs = self._create_filesystem_idempotent(
            fs_name, group_name, size_bytes,
            client=client, auth_required=auth_required)
        fs_uid = fs['uid']

        if self._is_isolated_wekafs(share):
            self._ensure_group_policies(share, fs_uid)

        export_locations = self._build_export_locations(
            share, fs_name, fs_uid, share_proto)

        LOG.info(
            "Share %s created successfully (fs_uid=%s)", share['id'], fs_uid)
        return export_locations

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from a snapshot; the copy runs in background.

        Returns STATUS_CREATING_FROM_SNAPSHOT immediately, for Manila to
        poll via get_share_status.
        """
        share_proto = share['share_proto'].upper()

        if share_proto == _NFS_PROTO and not self._nfs_server:
            raise exception.ShareBackendException(
                msg=_(
                    'weka_nfs_server must be configured to create '
                    'an NFS share from a snapshot'
                )
            )

        snap_name = self._snapshot_name(snapshot['id'])

        # Snapshot, source fs and new fs share one org.
        client = self._client_for_share(share)

        snap = client.get_snapshot_by_name(snap_name)
        if not snap:
            raise exception.ShareSnapshotNotFound(snapshot_id=snapshot['id'])

        src_fs = client.get_filesystem(snap['filesystemUid'])
        src_fs_name = src_fs['name']

        new_fs_name = self._share_name(share['id'])
        group_name = self.configuration.safe_get('weka_filesystem_group')
        size_bytes = weka_utils.gb_to_bytes(share['size'])

        fs = self._create_filesystem_idempotent(
            new_fs_name, group_name, size_bytes,
            client=client,
            auth_required=self._is_isolated_wekafs(share))
        fs_uid = fs['uid']

        export_locations = self._build_export_locations(
            share, new_fs_name, fs_uid, share_proto)

        with self._async_copies_lock:
            self._async_copies[share['id']] = {
                'status': constants.STATUS_CREATING_FROM_SNAPSHOT,
                'fs_uid': fs_uid,
                'fs_name': new_fs_name,
            }

        LOG.debug(
            "Starting background copy for share %s from snapshot %s "
            "(src fs: %s, snap: %s, proto: %s)",
            share['id'], snapshot['id'], src_fs_name, snap_name, share_proto,
        )

        copy_thread = threading.Thread(
            target=self._run_snapshot_copy,
            args=(share, snapshot, snap, src_fs_name, new_fs_name,
                  share_proto),
        )
        copy_thread.daemon = True
        copy_thread.start()

        return {
            'status': constants.STATUS_CREATING_FROM_SNAPSHOT,
            'export_locations': export_locations,
        }

    def _run_snapshot_copy(self, share, snapshot, snap,
                           src_fs_name, new_fs_name, share_proto):
        """Background worker: copy the data, then record the status."""
        share_id = share['id']
        try:
            if share_proto == _NFS_PROTO:
                self._copy_snapshot_nfs(
                    share, snapshot, snap, src_fs_name, new_fs_name)
            else:
                self._copy_snapshot_wekafs(
                    share, snapshot, snap, src_fs_name, new_fs_name)
            LOG.info(
                "Background copy complete for share %s from snapshot %s",
                share_id, snapshot['id'],
            )
            with self._async_copies_lock:
                entry = self._async_copies.get(share_id, {})
                entry['status'] = constants.STATUS_AVAILABLE
                self._async_copies[share_id] = entry
        except Exception:
            LOG.exception(
                "Background copy failed for share %s from snapshot %s",
                share_id, snapshot['id'],
            )
            with self._async_copies_lock:
                entry = self._async_copies.get(share_id, {})
                entry['status'] = constants.STATUS_ERROR
                self._async_copies[share_id] = entry

    def _rsync_snapshot(self, src_snap_dir, dst_mnt):
        """Rsync a snapshot directory into a destination mount."""
        LOG.debug("Rsyncing snapshot data from %s to %s",
                  src_snap_dir, dst_mnt)
        weka_privsep.rsync(
            src_snap_dir.rstrip('/') + '/',
            dst_mnt.rstrip('/') + '/',
        )

    def _copy_snapshot_nfs(self, share, snapshot, snap,
                           src_fs_name, new_fs_name):
        """Copy snapshot data through temporary NFS mounts."""
        nfs_server = self._nfs_server
        if not nfs_server:
            raise exception.ManilaException(
                message=_('weka_nfs_server must be configured for '
                          'create_share_from_snapshot'))

        snap_name = self._snapshot_name(snapshot['id'])

        # Local IP that routes to the NFS server.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((nfs_server, 2049))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = socket.gethostbyname(socket.gethostname())
        finally:
            s.close()

        tmp_cg_name = 'manila-snap-{}'.format(share['id'][:8])
        cg_uid = None
        rule_uid = None
        src_mnt = tempfile.mkdtemp(prefix='manila_weka_snap_src_')
        dst_mnt = tempfile.mkdtemp(prefix='manila_weka_snap_dst_')
        src_mounted = False
        dst_mounted = False

        try:
            cg = self._client.create_client_group(tmp_cg_name)
            cg_uid = cg['uid']
            rule = self._client.add_client_group_rule(
                cg_uid, 'IP', local_ip)
            rule_uid = rule.get('uid') if isinstance(rule, dict) else None

            self._client.create_nfs_permission(
                client_group=tmp_cg_name,
                fs_uid=src_fs_name,
                path='/',
                access_type='RO',
                squash=False,
            )
            self._client.create_nfs_permission(
                client_group=tmp_cg_name,
                fs_uid=new_fs_name,
                path='/',
                access_type='RW',
                squash=False,
            )

            # The new permissions take a moment to reach the NFS servers,
            # so the mount retries rather than blocking on a sleep.
            _nfs_mount_with_retry(
                '{}:/{}'.format(nfs_server, src_fs_name),
                src_mnt,
            )
            src_mounted = True

            _nfs_mount_with_retry(
                '{}:/{}'.format(nfs_server, new_fs_name),
                dst_mnt,
            )
            dst_mounted = True

            snap_access_point = snap.get('accessPoint') or snap_name
            snap_dir = os.path.join(
                src_mnt, '.snapshots', snap_access_point)
            self._rsync_snapshot(snap_dir, dst_mnt)
            LOG.info(
                "Copied snapshot %s content to filesystem %s via NFS",
                snap_name, new_fs_name,
            )
        finally:
            if dst_mounted:
                try:
                    weka_privsep.umount(dst_mnt)
                except Exception as e:
                    LOG.warning("Failed to umount %s: %s", dst_mnt, e)
            if src_mounted:
                try:
                    weka_privsep.umount(src_mnt)
                except Exception as e:
                    LOG.warning("Failed to umount %s: %s", src_mnt, e)
            for mnt in (src_mnt, dst_mnt):
                try:
                    os.rmdir(mnt)
                except Exception:
                    pass
            try:
                for perm in self._client.list_nfs_permissions():
                    if perm.get('group') == tmp_cg_name:
                        try:
                            self._client.delete_nfs_permission(perm['uid'])
                        except Exception:
                            pass
            except Exception as e:
                LOG.warning(
                    "Failed to clean up NFS permissions for %s: %s",
                    tmp_cg_name, e)
            if cg_uid:
                if rule_uid:
                    try:
                        self._client.delete_client_group_rule(
                            cg_uid, rule_uid)
                    except Exception:
                        pass
                try:
                    self._client.delete_client_group(cg_uid)
                except Exception as e:
                    LOG.warning(
                        "Failed to delete client group %s: %s",
                        tmp_cg_name, e)

    def _copy_snapshot_wekafs(self, share, snapshot, snap,
                              src_fs_name, new_fs_name):
        """Copy snapshot data via WEKAFS POSIX mounts (context manager)."""
        snap_name = self._snapshot_name(snapshot['id'])
        num_cores = self.configuration.safe_get('weka_num_cores')
        net = self.configuration.safe_get('weka_net_device')
        # backends=None is deliberate: the Manila host is already a joined
        # Weka client, and passing backends=<addr>/<fs> triggers a second
        # cluster attachment that fails with exit 3 ("Another client
        # container is already attached").  Do not use _get_backends()
        # here.  One org token covers both mounts.
        auth_token_path = self._org_token_file(share.get('project_id'))

        src_mnt = tempfile.mkdtemp(prefix='manila_weka_snap_src_')
        dst_mnt = tempfile.mkdtemp(prefix='manila_weka_snap_dst_')
        try:
            with weka_posix.WekaMount(
                backends=None,
                fs_name=src_fs_name,
                mount_point=src_mnt,
                auth_token_path=auth_token_path,
                num_cores=num_cores,
                net=net,
            ):
                with weka_posix.WekaMount(
                    backends=None,
                    fs_name=new_fs_name,
                    mount_point=dst_mnt,
                    auth_token_path=auth_token_path,
                    num_cores=num_cores,
                    net=net,
                ):
                    snap_access_point = (
                        snap.get('accessPoint') or snap_name)
                    snap_dir = os.path.join(
                        src_mnt, '.snapshots', snap_access_point)
                    self._rsync_snapshot(snap_dir, dst_mnt)
                    LOG.info(
                        "Copied snapshot %s to filesystem %s via WekaFS",
                        snap_name, new_fs_name,
                    )
        finally:
            for mnt in (src_mnt, dst_mnt):
                try:
                    os.rmdir(mnt)
                except Exception:
                    pass

    def get_share_status(self, share, share_server=None):
        """Report an async copy's status from the in-memory state map.

        A missing entry means the process restarted mid-copy: report
        'error' so the share can be deleted and the clone retried.
        """
        with self._async_copies_lock:
            entry = self._async_copies.get(share['id'])

        if entry is None:
            LOG.warning(
                "No in-memory copy state for share %s; the process may "
                "have restarted mid-copy.  Reporting 'error' so the "
                "share can be deleted and the clone re-attempted.",
                share['id'],
            )
            return {'status': constants.STATUS_ERROR}

        state = entry.get('status')

        if state == constants.STATUS_AVAILABLE:
            fs_name = entry.get(
                'fs_name', self._share_name(share['id']))
            fs_uid = entry.get('fs_uid', '')
            share_proto = share['share_proto'].upper()
            export_locations = self._build_export_locations(
                share, fs_name, fs_uid, share_proto)
            return {
                'status': constants.STATUS_AVAILABLE,
                'export_locations': export_locations,
            }
        elif state == constants.STATUS_ERROR:
            return {'status': constants.STATUS_ERROR}
        elif state == constants.STATUS_CREATING_FROM_SNAPSHOT:
            return {'status': constants.STATUS_CREATING_FROM_SNAPSHOT}
        else:
            return {'status': state}

    def delete_share(self, context, share, share_server=None):
        """Delete a share's filesystem; idempotent if already gone."""
        fs_name = self._share_name(share['id'])
        LOG.debug(
            "Deleting share %s (Weka FS '%s')", share['id'], fs_name)

        # The project's org is intentionally retained after its last
        # share is deleted.
        client = self._client_for_share(share)

        fs = client.get_filesystem_by_name(fs_name)
        if not fs:
            LOG.info(
                "Filesystem '%s' not found — share %s already deleted",
                fs_name, share['id'],
            )
            return

        fs_uid = fs['uid']

        # Per-share policies must go while the filesystem still exists;
        # shared group policies are left in place.
        if self._is_isolated_wekafs(share):
            try:
                self._cleanup_wekafs_policies(share, client, fs_uid)
            except Exception as exc:
                LOG.warning(
                    "Failed to clean up security policies for share %s: %s",
                    share['id'], exc,
                )

        # Unmount takes no mount options, so no auth token is needed.
        mount_point = self._mount_point(fs_name)
        if weka_posix.WekaMount.is_mounted(mount_point):
            try:
                mnt = weka_posix.WekaMount(
                    backends=self._get_backends(),
                    fs_name=fs_name,
                    mount_point=mount_point,
                )
                mnt.unmount(force=True)
            except Exception:
                # Deleting the filesystem under a stuck mount would wedge
                # the share manager; fail the delete instead.
                LOG.exception(
                    "Failed to unmount %s during delete of share %s",
                    mount_point, share['id'],
                )
                raise

        try:
            client.delete_filesystem(fs_uid)
        except weka_exc.WekaNotFound:
            pass  # already gone

        LOG.info("Share %s deleted", share['id'])

    def extend_share(self, share, new_size, share_server=None):
        """Extend share capacity to *new_size* GiB."""
        client = self._client_for_share(share)
        fs_uid = self._get_fs_uid_for_share(share, client=client)
        new_bytes = weka_utils.gb_to_bytes(new_size)
        LOG.debug(
            "Extending share %s to %s GiB", share['id'], new_size)
        client.update_filesystem(fs_uid, total_capacity=new_bytes)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrink to *new_size* GiB unless in-use capacity exceeds it."""
        client = self._client_for_share(share)
        fs_uid = self._get_fs_uid_for_share(share, client=client)
        fs = client.get_filesystem(fs_uid)
        used_bytes = fs.get('used_total', fs.get('usedSizeBytes', 0)) or 0
        new_bytes = weka_utils.gb_to_bytes(new_size)

        if used_bytes > new_bytes:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        LOG.debug(
            "Shrinking share %s to %s GiB", share['id'], new_size)
        client.update_filesystem(fs_uid, total_capacity=new_bytes)

    def get_backend_info(self, context):
        """Return stable backend identifiers used by ensure_shares."""
        return {
            'weka_api_server': (
                self.configuration.safe_get('weka_api_server')),
            'weka_mount_point_base': (
                self.configuration.safe_get('weka_mount_point_base')),
        }

    def ensure_shares(self, context, shares):
        """Re-verify every share, in one list_filesystems call.

        A share whose filesystem is gone is reported STATUS_ERROR.
        """
        fs_by_name = {
            fs['name']: fs for fs in self._client.list_filesystems() or []}

        updates = {}
        for share in shares:
            try:
                export_locations = self._ensure_share(
                    context, share, fs_by_name=fs_by_name)
                updates[share['id']] = {
                    'export_locations': export_locations}
            except exception.ShareNotFound:
                updates[share['id']] = {
                    'status': constants.STATUS_ERROR}
        return updates

    def _ensure_share(self, context, share, share_server=None,
                      fs_by_name=None):
        """Verify one share is exported and return its export locations."""
        fs_name = self._share_name(share['id'])
        share_proto = share['share_proto'].upper()
        # Per-project orgs are invisible to the admin session's list, so
        # isolated shares resolve through the org client, not the cache.
        if self._is_isolated_wekafs(share):
            # This is a periodic health check and must stay side-effect
            # free: if the org is gone, report the share as missing
            # rather than let _org_client re-provision an empty one.
            project_id = share.get('project_id')
            if not self._client.get_organization_by_name(
                    self._org_name(project_id)):
                raise exception.ShareNotFound(share_id=share['id'])
            fs = self._org_client(
                project_id).get_filesystem_by_name(fs_name)
        elif fs_by_name is not None:
            fs = fs_by_name.get(fs_name)
        else:
            fs = self._client.get_filesystem_by_name(fs_name)
        if not fs:
            raise exception.ShareNotFound(share_id=share['id'])

        fs_uid = fs['uid']

        mount_point = self._mount_point(fs_name)
        if (share_proto == _WEKAFS_PROTO
                and not weka_posix.WekaMount.is_mounted(mount_point)):
            LOG.info(
                "Re-mounting WekaFS share %s at %s",
                share['id'], mount_point,
            )
            mnt = weka_posix.WekaMount(
                backends=self._get_backends(),
                fs_name=fs_name,
                mount_point=mount_point,
                auth_token_path=self._org_token_file(
                    share.get('project_id')),
                num_cores=self.configuration.safe_get('weka_num_cores'),
                net=self.configuration.safe_get('weka_net_device'),
            )
            mnt.mount()

        return self._build_export_locations(
            share, fs_name, fs_uid, share_proto)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, update_rules=None, share_server=None):
        """Update access rules, in either contract mode.

        A full sync (empty add/delete/update) must leave the backend
        matching access_rules exactly, so rules are applied *and* stale
        backend state is pruned -- otherwise access revoked while the
        share manager was down would stay live on the cluster.
        """
        share_proto = share['share_proto'].upper()

        add_rules = list(add_rules or [])
        delete_rules = list(delete_rules or [])
        update_rules = list(update_rules or [])

        # Full sync: Manila passes every rule in access_rules and leaves
        # add/delete/update empty.
        full_sync = not (add_rules or delete_rules or update_rules)
        if full_sync:
            add_rules = list(access_rules or [])

        apply_rules = add_rules + update_rules

        # create_share rejects every other protocol, so there is no third
        # branch to write here.
        if share_proto == _NFS_PROTO:
            return self._update_nfs_access(
                share, apply_rules, delete_rules, full_sync)
        return self._update_wekafs_access(
            share, apply_rules, delete_rules, full_sync)

    def _update_nfs_access(self, share, add_rules, delete_rules, full_sync):
        """Add / delete NFS permissions on the Weka cluster."""
        rule_state_map = {}
        fs_name = self._share_name(share['id'])

        for rule in add_rules or []:
            if rule['access_type'] != 'ip':
                LOG.warning(
                    "NFS shares only support 'ip' access type; "
                    "skipping rule %s (type=%s)",
                    rule['access_id'], rule['access_type'],
                )
                rule_state_map[rule['access_id']] = {'state': 'error'}
                continue
            if _is_ipv6(rule['access_to']):
                LOG.warning(
                    "Ignoring IPv6 access rule %s: Weka supports IPv4 "
                    "rules only.", rule['access_id'],
                )
                continue
            try:
                self._apply_nfs_rule(share, fs_name, rule)
                rule_state_map[rule['access_id']] = {'state': 'active'}
            except Exception as exc:
                LOG.error(
                    "Failed to add NFS rule %s on share %s: %s",
                    rule['access_id'], share['id'], exc,
                )
                rule_state_map[rule['access_id']] = {'state': 'error'}

        for rule in delete_rules or []:
            try:
                self._remove_nfs_rule(fs_name, rule)
            except Exception as exc:
                LOG.warning(
                    "Failed to delete NFS rule %s: %s",
                    rule['access_id'], exc,
                )

        if full_sync:
            self._prune_nfs_rules(share, fs_name, add_rules)

        return rule_state_map

    def _prune_nfs_rules(self, share, fs_name, expected_rules):
        """Full sync: drop permissions and groups no rule backs.

        Driven off this filesystem's own permissions, so it can never
        touch another share's resources.
        """
        prefix = self._nfs_cg_name(share['id'])
        expected = {
            self._nfs_cg_name(share['id'], rule['access_id'])
            for rule in expected_rules or []
        }
        stale = set()
        for perm in self._client.list_nfs_permissions() or []:
            perm_fs, perm_cg = self._perm_keys(perm)
            if perm_fs != fs_name:
                continue
            if not perm_cg.startswith(prefix) or perm_cg in expected:
                continue
            try:
                self._client.delete_nfs_permission(perm['uid'])
                stale.add(perm_cg)
            except Exception as exc:
                LOG.warning(
                    "Failed to prune stale NFS permission for group %s "
                    "on share %s: %s", perm_cg, share['id'], exc,
                )
        for cg_name in stale:
            try:
                self._delete_client_group_by_name(cg_name)
            except Exception as exc:
                LOG.warning(
                    "Failed to prune stale NFS client group %s on "
                    "share %s: %s", cg_name, share['id'], exc,
                )
        if stale:
            LOG.info(
                "Pruned %d stale NFS access resource(s) on share %s "
                "during full sync.", len(stale), share['id'],
            )

    def _apply_nfs_rule(self, share, fs_name, rule):
        """Idempotently apply one NFS ip rule: group, rule, permission."""
        nfs_type = (
            'RW' if rule['access_level'] == constants.ACCESS_LEVEL_RW
            else 'RO')
        cg_name = self._nfs_cg_name(share['id'], rule['access_id'])
        try:
            weka_ip = _cidr_to_weka_ip(rule['access_to'])
        except ValueError:
            raise exception.InvalidShareAccess(
                reason=_(
                    'Weka driver supports IPv4 access rules only; '
                    '"%s" is not a valid IPv4 address or network.'
                ) % rule['access_to']
            )

        cg = self._get_client_group_by_name(cg_name)
        if cg is None:
            cg = self._client.create_client_group(cg_name)
            existing_ips = set()
        else:
            detail = self._client.get_client_group(cg['uid'])
            # Addresses come back under 'rule', not 'ip'; DNS rules in
            # the same group never match an ip access rule.
            existing_ips = {
                _norm_weka_ip(r['rule'])
                for r in detail.get('rules', [])
                if r.get('type') == 'IP' and r.get('rule')
            }
        if _norm_weka_ip(weka_ip) not in existing_ips:
            try:
                self._client.add_client_group_rule(
                    cg['uid'], 'IP', weka_ip)
            except weka_exc.WekaApiError as exc:
                # The IP may already be stored in a normalized form we
                # failed to match; keep going so the export permission
                # still gets reconciled (e.g. an ro->rw change).
                if not _is_already_exists_error(exc):
                    raise

        perm = self._find_nfs_permission(fs_name, cg_name)
        if perm is None:
            self._client.create_nfs_permission(
                client_group=cg_name, fs_uid=fs_name, path='/',
                access_type=nfs_type, squash=False)
        elif perm.get('permission_type') != nfs_type:
            self._client.delete_nfs_permission(perm['uid'])
            self._client.create_nfs_permission(
                client_group=cg_name, fs_uid=fs_name, path='/',
                access_type=nfs_type, squash=False)
        LOG.debug(
            "Applied NFS %s access for %s on share %s",
            nfs_type, rule['access_to'], share['id'],
        )

    def _get_client_group_by_name(self, name):
        """Return the NFS client group dict with this name, or None."""
        for cg in self._client.list_client_groups() or []:
            if cg.get('name') == name:
                return cg
        return None

    def _find_nfs_permission(self, fs_name, cg_name):
        """Return the NFS permission for (filesystem, group), or None."""
        for perm in self._client.list_nfs_permissions() or []:
            if self._perm_keys(perm) == (fs_name, cg_name):
                return perm
        return None

    def _delete_client_group_by_name(self, name):
        """Delete the NFS client group with this name if it exists."""
        cg = self._get_client_group_by_name(name)
        if cg is None:
            return
        try:
            self._client.delete_client_group(cg['uid'])
        except weka_exc.WekaNotFound:
            pass

    def _update_wekafs_access(self, share, add_rules, delete_rules,
                              full_sync):
        """Apply WEKAFS rules as per-share Weka security policies.

        A share whose type sets weka:security_policy_group is governed
        by the shared group policies attached at create_share, so rules
        are accepted as-is.  Otherwise each ip rule maps to the share's
        own rw or ro policy.  Non-ip rules grant only the org mount credential,
        which every rule returns as its access_key.  The access model is
        described in the admin doc.
        """
        project_id = share.get('project_id')
        org_client = self._org_client(project_id)
        mount_password = self._org_mount_password(project_id)

        if add_rules:
            try:
                org_client.create_user(
                    self._org_mount_user(), 'Regular', mount_password)
            except weka_exc.WekaApiError as exc:
                # The mount user is shared by every share in the project,
                # so it usually exists already.
                if not _is_already_exists_error(exc):
                    raise

        rule_state_map = {}

        # The shared group attached at create_share governs access, so
        # per-rule IPs are a no-op here.
        if self._share_policy_group(share) is not None:
            for rule in add_rules or []:
                LOG.warning(
                    "WEKAFS share %s uses security-policy group access; "
                    "per-rule entry %s (type=%s) accepted as active.",
                    share['id'], rule['access_id'], rule['access_type'],
                )
                rule_state_map[rule['access_id']] = {
                    'state': 'active', 'access_key': mount_password}
            return rule_state_map

        # Per-share rw/ro policies.  The filesystem UID is only
        # needed to attach or detach a policy — ip rules and a full sync,
        # whose pruning can empty (and so detach) one.
        ip_work = any(
            r.get('access_type') == 'ip'
            for r in list(add_rules or []) + list(delete_rules or []))
        fs_uid = None
        if ip_work or full_sync:
            fs = org_client.get_filesystem_by_name(
                self._share_name(share['id']))
            fs_uid = fs['uid'] if fs else None

        for rule in add_rules or []:
            if rule['access_type'] != 'ip':
                # user/cert rules map to no IP policy: they grant the
                # org-boundary credential without an IP restriction.
                LOG.warning(
                    "WEKAFS rule %s (type=%s) grants the org-boundary "
                    "mount credential; no per-share IP policy created.",
                    rule['access_id'], rule['access_type'],
                )
                rule_state_map[rule['access_id']] = {
                    'state': 'active', 'access_key': mount_password}
                continue
            if _is_ipv6(rule['access_to']):
                LOG.warning(
                    "Ignoring IPv6 access rule %s: Weka supports IPv4 "
                    "rules only.", rule['access_id'],
                )
                continue
            try:
                self._apply_wekafs_rule(org_client, share, fs_uid, rule)
                rule_state_map[rule['access_id']] = {
                    'state': 'active', 'access_key': mount_password}
            except Exception as exc:
                LOG.error(
                    "Failed to apply WEKAFS rule %s on share %s: %s",
                    rule['access_id'], share['id'], exc,
                )
                rule_state_map[rule['access_id']] = {'state': 'error'}

        for rule in delete_rules or []:
            try:
                self._remove_wekafs_rule(org_client, share, fs_uid, rule)
            except Exception as exc:
                LOG.warning(
                    "Failed to remove WEKAFS rule %s on share %s: %s",
                    rule['access_id'], share['id'], exc,
                )

        if full_sync:
            self._prune_wekafs_rules(org_client, share, fs_uid, add_rules)

        return rule_state_map

    def _prune_wekafs_rules(self, org_client, share, fs_uid, expected_rules):
        """Full sync: drop per-share policy IPs no ip rule backs."""
        expected = {'rw': set(), 'ro': set()}
        for rule in expected_rules or []:
            if rule.get('access_type') != 'ip':
                continue
            if _is_ipv6(rule['access_to']):
                continue
            expected[self._rule_level(rule)].add(
                _policy_ip(rule['access_to']))

        pruned = 0
        for level in ('rw', 'ro'):
            pol = org_client.get_security_policy_by_name(
                self._wekafs_policy_name(share['id'], level))
            if pol is None:
                continue
            for weka_ip in self._policy_ips(pol):
                if weka_ip in expected[level]:
                    continue
                try:
                    self._policy_set_ip(
                        org_client, share, fs_uid, level, weka_ip,
                        present=False)
                    pruned += 1
                except Exception as exc:
                    LOG.warning(
                        "Failed to prune stale WEKAFS policy IP %s (%s) "
                        "on share %s: %s", weka_ip, level, share['id'], exc,
                    )
        if pruned:
            LOG.info(
                "Pruned %d stale WEKAFS policy IP(s) on share %s during "
                "full sync.", pruned, share['id'],
            )

    def _apply_wekafs_rule(self, org_client, share, fs_uid, rule):
        """Add an ip rule to its level's policy, clearing the other."""
        weka_ip = _policy_ip(rule['access_to'])
        level = self._rule_level(rule)
        other = 'ro' if level == 'rw' else 'rw'
        self._policy_set_ip(
            org_client, share, fs_uid, level, weka_ip, present=True)
        self._policy_set_ip(
            org_client, share, fs_uid, other, weka_ip, present=False)
        LOG.debug(
            "Applied WEKAFS %s access for %s on share %s",
            level, rule['access_to'], share['id'],
        )

    def _remove_wekafs_rule(self, org_client, share, fs_uid, rule):
        """Remove an ip rule's address from both per-share policies."""
        if rule.get('access_type') != 'ip':
            return
        if _is_ipv6(rule['access_to']):
            return
        weka_ip = _policy_ip(rule['access_to'])
        for level in ('rw', 'ro'):
            self._policy_set_ip(
                org_client, share, fs_uid, level, weka_ip, present=False)

    def _policy_set_ip(self, org_client, share, fs_uid, level, weka_ip,
                       present):
        """Add or remove *weka_ip* in a per-share level policy.

        Creates and attaches the policy on first use; detaches and
        deletes it once its last address is gone.
        """
        name = self._wekafs_policy_name(share['id'], level)
        read_only = (level == 'ro')
        pol = org_client.get_security_policy_by_name(name)

        if present:
            if pol is None:
                pol = org_client.create_security_policy(
                    name, ips=[weka_ip], action='Allow',
                    read_only=read_only)
            elif weka_ip not in self._policy_ips(pol):
                try:
                    org_client.update_security_policy(
                        self._policy_uid(pol), add_ips=[weka_ip])
                except weka_exc.WekaApiError as exc:
                    if not _is_already_exists_error(exc):
                        raise
            if fs_uid:
                try:
                    org_client.attach_fs_security_policies(
                        fs_uid, [self._policy_uid(pol)])
                except weka_exc.WekaApiError as exc:
                    # A second IP at the same level reuses one policy, so
                    # a re-attach is expected.
                    if not (_is_already_exists_error(exc)
                            or _is_already_attached_error(exc)):
                        raise
            return

        if pol is None:
            return
        current = self._policy_ips(pol)
        if weka_ip in current:
            try:
                org_client.update_security_policy(
                    self._policy_uid(pol), remove_ips=[weka_ip])
            except weka_exc.WekaNotFound:
                pass
            current = [i for i in current if i != weka_ip]
        if not current:
            if fs_uid:
                try:
                    org_client.detach_fs_security_policies(
                        fs_uid, [self._policy_uid(pol)])
                except weka_exc.WekaApiError:
                    pass
            try:
                org_client.delete_security_policy(self._policy_uid(pol))
            except weka_exc.WekaNotFound:
                pass

    def _remove_nfs_rule(self, fs_name, rule):
        """Delete a rule's export permission and its client group."""
        cg_names = set()
        for perm in self._client.list_nfs_permissions() or []:
            # The group name encodes the rule ID.
            perm_fs, cg_name = self._perm_keys(perm)
            if perm_fs != fs_name:
                continue
            if rule['access_id'][:8] in cg_name:
                self._client.delete_nfs_permission(perm['uid'])
                if cg_name:
                    cg_names.add(cg_name)
        for cg_name in cg_names:
            self._delete_client_group_by_name(cg_name)

    def _remove_all_nfs_permissions(self, fs_name):
        """Delete all export permissions and groups for a filesystem."""
        cg_names = set()
        for perm in self._client.list_nfs_permissions() or []:
            perm_fs, cg_name = self._perm_keys(perm)
            if perm_fs != fs_name:
                continue
            try:
                self._client.delete_nfs_permission(perm['uid'])
            except weka_exc.WekaNotFound:
                pass
            if cg_name:
                cg_names.add(cg_name)
        for cg_name in cg_names:
            self._delete_client_group_by_name(cg_name)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Create a snapshot of a share's underlying filesystem."""
        share = snapshot['share']
        client = self._client_for_share(share)
        fs_uid = self._get_fs_uid_for_share(share, client=client)
        snap_name = self._snapshot_name(snapshot['id'])

        LOG.debug(
            "Creating snapshot %s (name='%s') for share %s",
            snapshot['id'], snap_name, share['id'],
        )
        client.create_snapshot(
            fs_uid, name=snap_name, is_writable=False)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Delete a snapshot; idempotent if already gone."""
        share = snapshot['share']
        client = self._client_for_share(share)
        fs_uid = None
        try:
            fs_uid = self._get_fs_uid_for_share(share, client=client)
        except exception.ShareNotFound:
            LOG.warning(
                "Parent share %s not found — skipping snapshot delete",
                share['id'],
            )
            return

        snap_name = self._snapshot_name(snapshot['id'])
        LOG.debug(
            "Deleting snapshot %s (name='%s')",
            snapshot['id'], snap_name,
        )
        snap = client.get_snapshot_by_name(snap_name, fs_uid=fs_uid)
        if not snap:
            LOG.warning(
                "Snapshot '%s' not found — already deleted", snap_name)
            return
        try:
            client.delete_snapshot(snap['uid'])
        except weka_exc.WekaNotFound:
            pass

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Revert a share to a snapshot (in-place restore)."""
        share = snapshot['share']
        client = self._client_for_share(share)
        fs_uid = self._get_fs_uid_for_share(share, client=client)
        snap_name = self._snapshot_name(snapshot['id'])

        snap = client.get_snapshot_by_name(snap_name, fs_uid=fs_uid)
        if not snap:
            raise exception.ShareSnapshotNotFound(snapshot_id=snapshot['id'])

        LOG.debug(
            "Reverting share %s to snapshot %s",
            share['id'], snapshot['id'],
        )
        client.restore_snapshot(snap['uid'], fs_uid)

    def _update_share_stats(self, data=None):
        """Collect and publish backend statistics to Manila."""
        try:
            capacity = self._client.get_capacity()
        except Exception as exc:
            LOG.warning("Failed to fetch Weka capacity stats: %s", exc)
            capacity = {}

        total_bytes = capacity.get('totalBytes', 0) or 0
        used_bytes = capacity.get('usedBytes', 0) or 0
        free_bytes = max(0, total_bytes - used_bytes)

        cfg_get = self.configuration.safe_get
        group_name = cfg_get('weka_filesystem_group')
        reserved_pct = cfg_get('reserved_share_percentage')
        reserved_snap_pct = cfg_get('reserved_share_from_snapshot_percentage')
        reserved_extend_pct = cfg_get('reserved_share_extend_percentage')

        stats = {
            'vendor_name': 'Weka',
            'driver_version': DRIVER_VERSION,
            # Underscore-joined ("WEKAFS_NFS"), not a list: the scheduler
            # exact-matches this against a share type's extra spec, and
            # tempest calls .lower().split('_') on it.
            'storage_protocol': '_'.join(_SUPPORTED_PROTOCOLS),
            'total_capacity_gb': weka_utils.bytes_to_gb(total_bytes),
            'free_capacity_gb': weka_utils.bytes_to_gb(free_bytes),
            'reserved_percentage': reserved_pct,
            'reserved_snapshot_percentage': reserved_snap_pct,
            'reserved_share_extend_percentage': reserved_extend_pct,
            'max_over_subscription_ratio': cfg_get(
                'max_over_subscription_ratio'),
            'snapshot_support': True,
            # WEKAFS copy always works; NFS fails fast when unconfigured.
            'create_share_from_snapshot_support': True,
            'revert_to_snapshot_support': True,
            'mount_snapshot_support': False,
            'qos': False,
            'thin_provisioning': False,
            'pools': [{
                'pool_name': group_name,
                'total_capacity_gb': weka_utils.bytes_to_gb(total_bytes),
                'free_capacity_gb': weka_utils.bytes_to_gb(free_bytes),
                'reserved_percentage': reserved_pct,
                'reserved_snapshot_percentage': reserved_snap_pct,
                'reserved_share_extend_percentage': reserved_extend_pct,
            }],
        }
        super(WekaShareDriver, self)._update_share_stats(stats)

    def manage_existing(self, share, driver_options):
        """Adopt an existing Weka filesystem as a Manila share.

        Clears pre-existing NFS permissions so Manila owns access
        control.  Raises ManageInvalidShare for WEKAFS shares.
        """
        # Weka cannot move a filesystem between orgs, so a pre-existing
        # one can never satisfy WEKAFS isolation — its org-scoped
        # lifecycle ops would look in the wrong org and orphan it.  NFS
        # shares are not org-isolated and can still be managed.
        share_proto = share.get('share_proto', _WEKAFS_PROTO).upper()
        if share_proto == _WEKAFS_PROTO:
            raise exception.ManageInvalidShare(
                reason=_(
                    'Managing existing WEKAFS shares is not supported: '
                    'per-tenant isolation requires the filesystem to be '
                    'created by the driver inside the project\'s Weka '
                    'organization. Create the share with Manila instead.'))

        # 'manila manage' supplies the path; for NFS it is
        # '<server>:/<fs_name>'.
        fs_name = None
        for loc in share.get('export_locations', []):
            path = loc.get('path', '')
            if path:
                fs_name = (path.rsplit('/', 1)[-1]
                           if '/' in path else path)
                break

        if not fs_name:
            raise exception.ManageInvalidShare(
                reason=_(
                    'Cannot determine filesystem name from share export '
                    'location. Pass the filesystem name as the export '
                    'path to manila manage.'))

        fs = self._client.get_filesystem_by_name(fs_name)
        if not fs:
            raise exception.ManageInvalidShare(
                reason=_(
                    'Weka filesystem "%s" not found') % fs_name)

        size_bytes = (
            fs.get('total_budget', fs.get('totalCapacity', 0)) or 0)
        size_gb = max(1, int(weka_utils.bytes_to_gb(size_bytes)))
        fs_uid = fs.get('uid') or fs.get('id', '')

        export_locations = self._build_export_locations(
            share, fs_name, fs_uid, share_proto)

        # Manila must be the sole source of truth for access control.
        LOG.debug(
            "Clearing pre-existing NFS permissions for managed "
            "filesystem '%s'", fs_name)
        try:
            self._remove_all_nfs_permissions(fs_name)
        except Exception as exc:
            LOG.warning(
                "Failed to clear NFS permissions for '%s': %s",
                fs_name, exc)

        LOG.info(
            "Managed existing share %s (FS '%s', size %s GiB)",
            share['id'], fs_name, size_gb,
        )
        return {'size': size_gb, 'export_locations': export_locations}

    def unmanage(self, share):
        """Stop tracking a share; the Weka filesystem is left intact."""
        LOG.debug(
            "Unmanaging share %s — Weka filesystem '%s' preserved",
            share['id'], self._share_name(share['id']),
        )

    def get_network_allocations_number(self):
        """Return 0 — this driver manages its own networking via Weka."""
        return 0

    def _share_name(self, share_id):
        """Filesystem name for a share ID (32-char cluster limit)."""
        prefix = self.configuration.safe_get('weka_share_name_prefix')
        id_hex = share_id.replace('-', '')
        max_id_len = 32 - len(prefix)
        return prefix + id_hex[:max_id_len]

    def _share_name_from_share(self, share):
        """Attempt to derive filesystem name from a share model."""
        return self._share_name(share['id'])

    def _snapshot_name(self, snapshot_id):
        """Snapshot name for a snapshot ID (32-char cluster limit)."""
        id_hex = snapshot_id.replace('-', '')
        return 's_' + id_hex[:30]

    def _mount_point(self, fs_name):
        """Return the local mount point directory for a filesystem."""
        base = self.configuration.safe_get('weka_mount_point_base')
        return os.path.join(base, fs_name)

    def _get_backends(self):
        """Return the Weka backend address string for POSIX mounts."""
        return self.configuration.safe_get('weka_api_server') or ''

    def _org_name(self, project_id):
        """Organization name for a project: prefix + undashed project_id.

        Never truncated -- two projects sharing an org would break
        isolation.
        """
        pid = (project_id or '').replace('-', '')
        return '{}{}'.format(self._org_prefix, pid)

    def _derive_password(self, project_id, tag=''):
        """Derive a project password from weka_org_admin_secret.

        HMAC-SHA256 over project_id + *tag*, which namespaces principals
        (org admin vs mount user).  Nothing per-tenant is stored.
        """
        if not self._org_admin_secret:
            # do_setup requires it; fail loudly rather than derive
            # predictable credentials from an empty key.
            raise weka_exc.WekaConfigurationError(
                reason=_('weka_org_admin_secret is not set; cannot derive '
                         'per-organization credentials'))
        digest = hmac.new(
            self._org_admin_secret.encode('utf-8'),
            ((project_id or '') + tag).encode('utf-8'),
            hashlib.sha256).hexdigest()
        # A hex slice may hold no digit at all, so '1!' supplies the
        # digit and special Weka's complexity rules want.
        return 'Wk{}1!'.format(digest[:20])

    def _org_password(self, project_id):
        """Per-org TenantAdmin password (driver-internal; never exposed)."""
        return self._derive_password(project_id)

    def _org_mount_password(self, project_id):
        """Mount-user password handed to tenants via update_access."""
        return self._derive_password(project_id, ':mount')

    def _org_mount_user(self):
        """Least-privilege (Regular) username tenants use to mount."""
        return '{}-mnt'.format(self._org_user)

    @staticmethod
    def _policy_uid(policy):
        """Return a security policy's UID (Weka uses 'uid'; fall back id)."""
        return policy.get('uid') or policy.get('id')

    @staticmethod
    def _wekafs_policy_name(share_id, level):
        """Per-share policy name for an access level (rw/ro)."""
        return 'manila-{}-{}'.format(share_id[:8], level)

    @staticmethod
    def _nfs_cg_name(share_id, access_id=None):
        """Per-rule client group name; without access_id, the prefix."""
        return 'manila-{}-{}'.format(
            share_id[:8], access_id[:8] if access_id else '')

    @staticmethod
    def _perm_keys(perm):
        """(filesystem, group) of a permission, across payload shapes."""
        return (
            perm.get('filesystem', perm.get('filesystem_id', '')),
            perm.get('group', perm.get('client_group_name', '')),
        )

    @staticmethod
    def _rule_level(rule):
        """Map an access rule's level to a policy suffix (rw/ro)."""
        return ('rw' if rule['access_level'] == constants.ACCESS_LEVEL_RW
                else 'ro')

    @staticmethod
    def _policy_ips(policy):
        """Addresses a security policy currently matches.

        Asymmetric API: writes take ``ip``/``add_ip``, but a policy reads
        back its addresses under ``ips``.
        """
        return list(policy.get('ips') or policy.get('ip') or [])

    @staticmethod
    def _group_policy_name(group, level):
        """Shared policy name for a named group + level (rw/ro)."""
        return 'manila-grp-{}-{}'.format(group, level)

    @staticmethod
    def _parse_policy_groups(spec):
        """Parse weka_security_policy_group to {group: {level: [cidr]}}.

        A malformed entry is logged and skipped rather than failing
        driver startup.
        """
        groups = {}
        if not spec:
            return groups
        for entry in spec.split(';'):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(':')
            if len(parts) != 3:
                LOG.warning(
                    "Ignoring malformed weka_security_policy_group entry "
                    "(expected '<group>:<rw|ro>:<cidr,...>'): %s", entry)
                continue
            group = parts[0].strip()
            level = parts[1].strip().lower()
            if not group or level not in ('rw', 'ro'):
                LOG.warning(
                    "Ignoring weka_security_policy_group entry with an "
                    "invalid group/level: %s", entry)
                continue
            ips = [c.strip() for c in parts[2].split(',') if c.strip()]
            groups.setdefault(group, {}).setdefault(level, [])
            groups[group][level].extend(ips)
        return groups

    def _share_policy_group(self, share):
        """Named policy group from the share type, or None."""
        type_id = share.get('share_type_id')
        if not type_id:
            return None
        try:
            specs = share_types.get_share_type_extra_specs(type_id) or {}
        except Exception as exc:
            LOG.warning(
                "Could not read share type extra specs for share %s: %s",
                share.get('id'), exc)
            return None
        return specs.get(self._POLICY_GROUP_SPEC) or None

    def _ensure_group_policies(self, share, fs_uid):
        """Create (once per org) and attach a shared group's policies."""
        group = self._share_policy_group(share)
        if not group:
            return
        profile = self._policy_groups.get(group)
        if not profile:
            LOG.warning(
                "Share %s references unknown security policy group '%s' "
                "(not defined in weka_security_policy_group); no access "
                "policy attached.", share['id'], group)
            return
        org_client = self._org_client(share.get('project_id'))
        for level in ('rw', 'ro'):
            ips = profile.get(level) or []
            if not ips:
                continue
            name = self._group_policy_name(group, level)
            pol = org_client.get_security_policy_by_name(name)
            if pol is None:
                pol = org_client.create_security_policy(
                    name, ips=ips, action='Allow',
                    read_only=(level == 'ro'))
            try:
                org_client.attach_fs_security_policies(
                    fs_uid, [self._policy_uid(pol)])
            except weka_exc.WekaApiError as exc:
                if not (_is_already_exists_error(exc)
                        or _is_already_attached_error(exc)):
                    raise
        LOG.info(
            "Attached security-policy group '%s' to WEKAFS share %s",
            group, share['id'])

    def _cleanup_wekafs_policies(self, share, org_client, fs_uid):
        """Detach and delete the share's own policies.

        Shared ``manila-grp-*`` policies never match these names and are
        left in place.
        """
        for level in ('rw', 'ro'):
            name = self._wekafs_policy_name(share['id'], level)
            try:
                pol = org_client.get_security_policy_by_name(name)
            except Exception:
                pol = None
            if not pol:
                continue
            uid = self._policy_uid(pol)
            if fs_uid:
                try:
                    org_client.detach_fs_security_policies(fs_uid, [uid])
                except Exception:
                    pass
            try:
                org_client.delete_security_policy(uid)
            except weka_exc.WekaNotFound:
                pass
            except Exception as exc:
                LOG.warning(
                    "Failed to delete security policy '%s' for share %s: "
                    "%s", name, share['id'], exc)

    def _ensure_org(self, project_id):
        """Get-or-create the project's org; call with _org_lock held."""
        org_name = self._org_name(project_id)
        username = self._org_user
        password = self._org_password(project_id)
        org = self._client.get_organization_by_name(org_name)
        if org is None:
            LOG.info(
                "Creating Weka organization '%s' for project %s",
                org_name, project_id)
            try:
                self._client.create_organization(
                    org_name, username, password)
            except weka_exc.WekaApiError as exc:
                if not _is_already_exists_error(exc):
                    raise weka_exc.WekaOrgError(
                        reason='failed to create organization '
                               '{}: {}'.format(org_name, exc))
        return org_name, username, password

    def _org_client(self, project_id):
        """Cached API client authenticated to the project's own org.

        Raises WekaOrgError without a project_id: such a share would map
        to a shared org and break isolation.
        """
        if not project_id:
            raise weka_exc.WekaOrgError(
                reason='share has no project_id; cannot map it to a '
                       'per-tenant Weka organization')
        with self._org_lock:
            client = self._org_clients.get(project_id)
            if client is None:
                org_name, username, password = self._ensure_org(project_id)
                client = self._client.for_org(
                    org_name, username, password)
                self._org_clients[project_id] = client
            return client

    def _is_isolated_wekafs(self, share):
        """True for WEKAFS shares, which are always org-isolated."""
        return (share.get('share_proto') or '').upper() == _WEKAFS_PROTO

    def _client_for_share(self, share):
        """Org-scoped client for WEKAFS shares, admin client for NFS."""
        if self._is_isolated_wekafs(share):
            return self._org_client(share.get('project_id'))
        return self._client

    def _org_token_file(self, project_id):
        """Write the org's mount-token file (0600) and return its path."""
        client = self._org_client(project_id)
        token_dir = self._auth_token_dir
        try:
            os.makedirs(token_dir, mode=0o700, exist_ok=True)
            # makedirs' mode applies on creation only, so tighten an
            # existing dir too.
            try:
                os.chmod(token_dir, 0o700)
            except OSError:
                pass
            # basename() keeps the token inside token_dir even if the org
            # name ever picked up a separator.
            path = os.path.join(
                token_dir,
                os.path.basename('{}.json'.format(
                    self._org_name(project_id))))
            # mkstemp (0600, collision-free) plus an atomic rename, so a
            # mount never reads a half-written token.
            fd, tmp = tempfile.mkstemp(
                dir=token_dir, prefix='.tok-', suffix='.tmp')
            try:
                with os.fdopen(fd, 'w') as fh:
                    json.dump(client.auth_token_payload(), fh)
                os.replace(tmp, path)
            except OSError:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            return path
        except OSError as exc:
            raise weka_exc.WekaMountError(
                reason='failed to write auth token file: {}'.format(exc))

    def _get_fs_uid_for_share(self, share, client=None):
        """Resolve a share's filesystem UID.

        Prefers the UID cached in export metadata (cluster-global, so
        valid whatever *client* is), then the generated name, then the
        export path's name for managed shares.
        """
        client = client or self._client
        for loc in share.get('export_locations', []) or []:
            try:
                meta = loc.get('metadata') or {}
                if isinstance(meta, dict):
                    uid = meta.get('weka_fs_uid')
                else:
                    # Manila ORM object — iterate key/value pairs
                    uid = next(
                        (v for k, v in meta.items()
                         if k == 'weka_fs_uid'),
                        None)
                if uid:
                    return uid
            except (AttributeError, TypeError):
                pass

        fs_name = self._share_name(share['id'])
        fs = client.get_filesystem_by_name(fs_name)
        if fs:
            return fs['uid']

        # A managed share keeps its original filesystem name, which is
        # the last component of the export path.
        for loc in share.get('export_locations', []) or []:
            path = ''
            try:
                path = (loc.get('path', '')
                        if isinstance(loc, dict)
                        else str(getattr(loc, 'path', '')))
            except (AttributeError, TypeError):
                pass
            if path:
                candidate = (path.rsplit('/', 1)[-1]
                             if '/' in path else path)
                if ':' in candidate:
                    candidate = candidate.split(':', 1)[-1].lstrip('/')
                if candidate:
                    fs = client.get_filesystem_by_name(candidate)
                    if fs:
                        return fs['uid']

        raise exception.ShareNotFound(share_id=share['id'])

    def _ensure_filesystem_group(self, group_name):
        """Ensure the default filesystem group exists; create if not."""
        grp = self._client.get_filesystem_group_by_name(group_name)
        if grp:
            self._fs_group_uid = grp['uid']
            LOG.debug(
                "Using existing Weka filesystem group '%s' (uid=%s)",
                group_name, self._fs_group_uid,
            )
        else:
            LOG.info(
                "Creating Weka filesystem group '%s'", group_name)
            grp = self._client.create_filesystem_group(group_name)
            self._fs_group_uid = grp['uid']

    def _create_filesystem_idempotent(self, fs_name, group_name,
                                      size_bytes, client=None,
                                      auth_required=False):
        """Create a filesystem, or return the existing one."""
        client = client or self._client
        existing = client.get_filesystem_by_name(fs_name)
        if existing:
            LOG.debug(
                "Filesystem '%s' already exists — reusing uid=%s",
                fs_name, existing.get('uid'),
            )
            return existing
        try:
            return client.create_filesystem(
                name=fs_name,
                group_name=group_name,
                total_capacity=size_bytes,
                auth_required=auth_required,
            )
        except weka_exc.WekaConflict:
            # Race: created by another thread/request.
            fs = client.get_filesystem_by_name(fs_name)
            if fs:
                return fs
            raise
        except weka_exc.WekaCapacityError as e:
            message = _(
                "Insufficient capacity in Weka filesystem group "
                "'%(group)s' to create filesystem '%(fs)s' of "
                "%(size)s bytes: %(reason)s") % {
                    'group': group_name,
                    'fs': fs_name,
                    'size': size_bytes,
                    'reason': str(e),
            }
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

    def _build_export_locations(self, share, fs_name, fs_uid, share_proto):
        """Build the share's export location list."""
        backends = self._get_backends()
        if share_proto == _WEKAFS_PROTO:
            path = '{backends}/{fs_name}'.format(
                backends=backends, fs_name=fs_name)
        else:
            nfs_server = (
                self.configuration.safe_get('weka_nfs_server') or backends)
            path = '{server}:/{fs_name}'.format(
                server=nfs_server, fs_name=fs_name)

        metadata = {
            'weka_fs_uid': fs_uid,
            'weka_fs_name': fs_name,
        }
        # Tenant self-service: the org and mount username a client needs
        # to mint its own mount token.
        if share_proto == _WEKAFS_PROTO:
            project_id = share.get('project_id')
            if project_id:
                metadata['weka_org_name'] = self._org_name(project_id)
                metadata['weka_org_user'] = self._org_mount_user()
        return [{
            'path': path,
            'is_admin_only': False,
            'metadata': metadata,
        }]
