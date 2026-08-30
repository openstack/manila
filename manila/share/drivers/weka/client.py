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

"""Weka REST API client for the Manila share driver.

Implements the subset of the Weka v2 REST API used by the driver:
  - Filesystem lifecycle (CRUD + capacity management)
  - Filesystem groups
  - NFS client groups and permissions
  - Snapshots
  - Cluster status / capacity

All unit conversions (GiB <-> bytes) happen in driver.py.
This client works exclusively in bytes / raw API types.
"""

import threading
import time

from oslo_log import log as logging
import requests
from requests import adapters as req_adapters

from manila.share.drivers.weka import exceptions
from manila.share.drivers.weka import utils

LOG = logging.getLogger(__name__)

_API_V2 = '/api/v2'


def _is_capacity_error(message):
    """True if a Weka API error message indicates capacity exhaustion."""
    low = (message or '').lower()
    return 'capacity' in low and any(
        kw in low for kw in ('not enough', 'insufficient', 'no space')
    )


# Overridden from config (weka_api_timeout, weka_max_api_retries).
_DEFAULT_TIMEOUT = 30
_DEFAULT_RETRIES = 3


class WekaApiClient(object):
    """Client for the Weka REST API (v2).

    Thread-safe: a lock around token refresh keeps concurrent callers
    from re-logging in simultaneously.
    """

    def __init__(self, host, username, password,
                 organization='Root',
                 port=14000,
                 ssl_verify=True,
                 timeout=_DEFAULT_TIMEOUT,
                 max_retries=_DEFAULT_RETRIES,
                 pool_connections=4,
                 pool_maxsize=10):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._organization = organization
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._max_retries = max_retries
        # Retained so for_org() can reuse the same pool sizing.
        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize

        self._base_url = 'https://{host}:{port}{api}'.format(
            host=host, port=port, api=_API_V2)

        self._access_token = None
        self._refresh_token = None
        self._token_lock = threading.Lock()

        self._session = requests.Session()
        adapter = req_adapters.HTTPAdapter(
            max_retries=0,  # handled manually
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )
        self._session.mount('https://', adapter)
        self._session.mount('http://', adapter)

    def _url(self, path):
        """Return a full URL for the given API path."""
        return self._base_url + path

    def _headers(self):
        """Return HTTP headers including the current Bearer token."""
        headers = {'Content-Type': 'application/json'}
        if self._access_token:
            headers['Authorization'] = 'Bearer ' + self._access_token
        return headers

    def _raise_for_status(self, response, context=''):
        """Translate HTTP error responses into WekaApiError subclasses."""
        code = response.status_code
        if code < 400:
            return
        try:
            body = response.json()
            msg = body.get('message') or body.get('error') or str(body)
        except Exception:
            msg = response.text or 'no body'

        if context:
            msg = '{}: {}'.format(context, msg)

        if code == 401:
            raise exceptions.WekaAuthError(reason=msg)
        elif code == 404:
            raise exceptions.WekaNotFound(reason=msg)
        elif code == 409:
            raise exceptions.WekaConflict(reason=msg)
        elif code == 429:
            raise exceptions.WekaRateLimited(reason=msg)
        elif code == 400 and _is_capacity_error(msg):
            raise exceptions.WekaCapacityError(reason=msg)
        else:
            raise exceptions.WekaApiError(status_code=code, reason=msg)

    def _request(self, method, path, params=None, json=None,
                 _retry_auth=True):
        """Authenticated request: refresh on 401, back off on 429/5xx."""
        url = self._url(path)
        safe_params = utils.sanitize_log_params(params or {})
        safe_json = utils.sanitize_log_params(json or {})
        LOG.debug(
            "Weka API %s %s params=%s body=%s",
            method.upper(), path, safe_params, safe_json,
        )

        delay = 1.0
        last_exc = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=self._headers(),
                    params=params,
                    json=json,
                    verify=self._ssl_verify,
                    timeout=self._timeout,
                )
                if resp.status_code == 401 and _retry_auth:
                    LOG.debug("Weka API 401 — refreshing token and retrying")
                    self._refresh_or_login()
                    resp = self._session.request(
                        method, url,
                        headers=self._headers(),
                        params=params,
                        json=json,
                        verify=self._ssl_verify,
                        timeout=self._timeout,
                    )
                self._raise_for_status(resp, context=path)
                return resp
            except exceptions.WekaRateLimited as exc:
                last_exc = exc
            except exceptions.WekaApiError as exc:
                if exc.status_code and exc.status_code < 500:
                    raise
                last_exc = exc
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                # Retried like a 5xx: most often a stale keep-alive
                # connection closed server-side ("RemoteDisconnected").
                last_exc = exc

            if attempt < self._max_retries:
                LOG.warning(
                    "Transient Weka API error on attempt %d/%d, "
                    "retrying in %.1fs",
                    attempt + 1, self._max_retries, delay,
                )
                time.sleep(delay)
                delay *= 2.0

        raise last_exc

    def _get(self, path, params=None):
        return self._request('GET', path, params=params).json()

    def _post(self, path, json=None):
        return self._request('POST', path, json=json).json()

    def _put(self, path, json=None):
        return self._request('PUT', path, json=json).json()

    def _patch(self, path, json=None):
        return self._request('PATCH', path, json=json).json()

    def _delete(self, path, params=None):
        resp = self._request('DELETE', path, params=params)
        if resp.content:
            try:
                return resp.json()
            except Exception:
                pass
        return {}

    def login(self):
        """Obtain and store a new token pair (thread-safe)."""
        with self._token_lock:
            self._do_login()

    @staticmethod
    def _parse_lockout_seconds(body_text):
        """Parse a lockout duration in seconds from a 403 body, or None.

        Weka phrases it as "2 minutes", "90 seconds" or "1m55s".
        """
        import re
        low = (body_text or '').lower()
        # Compact "1m55s" form first — it is the most specific.
        m = re.search(r'(\d+)\s*m\s*(\d+)\s*s', low)
        if m:
            return int(m.group(1)) * 60 + int(m.group(2))
        m = re.search(r'(\d+)\s*minute', low)
        if m:
            return int(m.group(1)) * 60
        m = re.search(r'(\d+)\s*second', low)
        if m:
            return int(m.group(1))
        m = re.search(r'(\d+)\s*m\b', low)
        if m:
            return int(m.group(1)) * 60
        m = re.search(r'(\d+)\s*s\b', low)
        if m:
            return int(m.group(1))
        return None

    def _do_login(self):
        """Inner login; call with _token_lock held.

        Backs off through a "locked out" 403 (capped at 150 s) so
        init_host's retry loop cannot perpetuate the lockout.
        """
        LOG.debug("Logging in to Weka cluster at %s as user '%s' org '%s'",
                  self._host, self._username, self._organization)
        payload = {
            'username': self._username,
            'password': self._password,
            'org': self._organization,
        }
        resp = self._session.post(
            self._url('/login'),
            json=payload,
            verify=self._ssl_verify,
            timeout=self._timeout,
        )
        # Catch a lockout before _raise_for_status, so the init_host retry
        # loop backs off instead of perpetuating it.  Weka files the
        # message under varying keys, so scan the raw body.
        if resp.status_code == 403:
            body_text = resp.text or ''
            if 'locked out' in body_text.lower():
                duration = self._parse_lockout_seconds(body_text)
                # 125s clears a typical ~2 minute lockout.
                backoff = min((duration or 125) + 5, 150)
                LOG.warning(
                    "Weka login locked out (~%ss); backing off %ds before "
                    "failing so the lockout can clear",
                    duration if duration is not None else 'unknown', backoff,
                )
                time.sleep(backoff)
                raise exceptions.WekaApiError(
                    status_code=403,
                    reason='/login: {}'.format(body_text),
                )
        self._raise_for_status(resp, context='/login')
        data = resp.json().get('data', resp.json())
        self._access_token = data['access_token']
        self._refresh_token = data.get('refresh_token')
        LOG.debug("Weka login successful (token acquired)")

    def _refresh_or_login(self):
        """Refresh the access token, falling back to full login."""
        with self._token_lock:
            if self._refresh_token:
                try:
                    resp = self._session.post(
                        self._url('/login/refresh'),
                        json={'refresh_token': self._refresh_token},
                        verify=self._ssl_verify,
                        timeout=self._timeout,
                    )
                    if resp.status_code == 200:
                        data = resp.json().get('data', resp.json())
                        self._access_token = data['access_token']
                        if 'refresh_token' in data:
                            self._refresh_token = data['refresh_token']
                        LOG.debug("Weka access token refreshed")
                        return
                except Exception:
                    pass
            LOG.debug("Token refresh failed — performing full login")
            self._do_login()

    def for_org(self, organization, username, password):
        """Return a client logged in as *username* in *organization*.

        Weka binds filesystem operations to the session's org rather than
        to a request field, so WEKAFS isolation needs a client per org.
        """
        client = WekaApiClient(
            host=self._host,
            username=username,
            password=password,
            organization=organization,
            port=self._port,
            ssl_verify=self._ssl_verify,
            timeout=self._timeout,
            max_retries=self._max_retries,
            pool_connections=self._pool_connections,
            pool_maxsize=self._pool_maxsize,
        )
        client.login()
        return client

    def auth_token_payload(self):
        """Current tokens shaped as a ``weka user login`` token file."""
        return {
            'access_token': self._access_token,
            'refresh_token': self._refresh_token,
            'token_type': 'Bearer',
        }

    def get_cluster_status(self):
        return self._get('/cluster')

    def list_organizations(self):
        result = self._get('/organizations')
        return result.get('data', result)

    def get_organization_by_name(self, name):
        """Find an organization by name; returns None if not found."""
        for org in self.list_organizations():
            if org.get('name') == name:
                return org
        return None

    def create_organization(self, name, username, password,
                            ssd_quota=None, total_quota=None,
                            enforce_mount_netspace_access=False):
        """Create an org and its admin user (POST /organizations).

        Network-space mount enforcement is switched off: these tenants
        have no network space and isolate via auth tokens, and leaving
        the REST default on rejects every mount into the org ("Tenant N
        has no network spaces attached").
        """
        payload = {
            'name': name,
            'username': username,
            'password': password,
            'enforce_mount_netspace_access': enforce_mount_netspace_access,
        }
        if ssd_quota is not None:
            payload['ssd_quota'] = ssd_quota
        if total_quota is not None:
            payload['total_quota'] = total_quota
        result = self._post('/organizations', json=payload)
        return result.get('data', result)

    def delete_organization(self, org_uid):
        return self._delete(
            '/organizations/{uid}'.format(uid=org_uid))

    def create_user(self, username, role, password):
        """Create a user in the session's org (POST /users).

        Weka has no per-request org field, so call this on an org-scoped
        client.  *role* is capitalized: 'TenantAdmin', 'Regular', etc.
        """
        payload = {
            'username': username,
            'role': role,
            'password': password,
        }
        result = self._post('/users', json=payload)
        return result.get('data', result)

    def list_filesystems(self):
        result = self._get('/fileSystems')
        return result.get('data', result)

    def get_filesystem(self, fs_uid):
        result = self._get('/fileSystems/{uid}'.format(uid=fs_uid))
        return result.get('data', result)

    def get_filesystem_by_name(self, name):
        """Find a filesystem by name, or None."""
        for fs in self.list_filesystems():
            if fs.get('name') == name:
                return fs
        return None

    def create_filesystem(self, name, group_name, total_capacity,
                          ssd_capacity=None,
                          obs_buckets=None,
                          encrypted=False,
                          auth_required=False,
                          allow_no_space=False,
                          data_reduction=None):
        payload = {
            'name': name,
            'group_name': group_name,
            'total_capacity': total_capacity,
            'encrypted': encrypted,
            'auth_required': auth_required,
        }
        if ssd_capacity is not None:
            payload['ssd_capacity'] = ssd_capacity
        if obs_buckets:
            payload['obs_buckets'] = obs_buckets
        if data_reduction is not None:
            payload['data_reduction'] = data_reduction
        result = self._post('/fileSystems', json=payload)
        return result.get('data', result)

    def update_filesystem(self, fs_uid, name=None, total_capacity=None,
                          ssd_capacity=None, auth_required=None,
                          allow_no_space=None, data_reduction=None):
        payload = {}
        if name is not None:
            payload['name'] = name
        if total_capacity is not None:
            payload['total_capacity'] = total_capacity
        if ssd_capacity is not None:
            payload['ssd_capacity'] = ssd_capacity
        if auth_required is not None:
            payload['auth_required'] = auth_required
        if data_reduction is not None:
            payload['data_reduction'] = data_reduction
        result = self._put(
            '/fileSystems/{uid}'.format(uid=fs_uid), json=payload)
        return result.get('data', result)

    def delete_filesystem(self, fs_uid, purge_from_obs=False):
        params = {}
        if purge_from_obs:
            params['purge_from_obs'] = True
        return self._delete(
            '/fileSystems/{uid}'.format(uid=fs_uid), params=params or None)

    def list_filesystem_groups(self):
        result = self._get('/fileSystemGroups')
        return result.get('data', result)

    def get_filesystem_group(self, group_uid):
        result = self._get(
            '/fileSystemGroups/{uid}'.format(uid=group_uid))
        return result.get('data', result)

    def get_filesystem_group_by_name(self, name):
        """Find a filesystem group by name; returns None if not found."""
        for grp in self.list_filesystem_groups():
            if grp.get('name') == name:
                return grp
        return None

    def create_filesystem_group(self, name, target_ssd_retention=None,
                                start_demote=None):
        payload = {'name': name}
        if target_ssd_retention is not None:
            payload['target_ssd_retention'] = target_ssd_retention
        if start_demote is not None:
            payload['start_demote'] = start_demote
        result = self._post('/fileSystemGroups', json=payload)
        return result.get('data', result)

    def list_nfs_permissions(self):
        result = self._get('/nfs/permissions')
        return result.get('data', result)

    def create_nfs_permission(self, client_group, fs_uid, path,
                              access_type='RW',
                              squash=None, anon_uid=None, anon_gid=None):
        """Create an NFS export permission (POST /nfs/permissions).

        Weka v5 keys on names, not UIDs: pass the filesystem name as
        *fs_uid* and the client group name as *client_group*.
        """
        payload = {
            'group': client_group,
            'filesystem': fs_uid,
            'path': path,
            'permission_type': access_type,
            'supported_versions': ['V3', 'V4'],
        }
        if squash is not None:
            payload['root_squashing'] = squash
        if anon_uid is not None:
            payload['anon_uid'] = anon_uid
        if anon_gid is not None:
            payload['anon_gid'] = anon_gid
        result = self._post('/nfs/permissions', json=payload)
        return result.get('data', result)

    def delete_nfs_permission(self, permission_uid):
        return self._delete(
            '/nfs/permissions/{uid}'.format(uid=permission_uid))

    def list_client_groups(self):
        result = self._get('/nfs/clientGroups')
        return result.get('data', result)

    def create_client_group(self, name):
        payload = {'name': name}
        result = self._post('/nfs/clientGroups', json=payload)
        return result.get('data', result)

    def add_client_group_rule(self, group_uid, rule_type, rule_value):
        """Add a rule to a client group (POST .../{uid}/rules).

        Weka v5 takes {'ip': '<IP/dotted-mask>'} or {'dns': '<pattern>'}.
        """
        rule_type_lower = rule_type.lower()
        if rule_type_lower == 'ip':
            payload = {'ip': rule_value}
        else:
            payload = {'dns': rule_value}
        result = self._post(
            '/nfs/clientGroups/{uid}/rules'.format(uid=group_uid),
            json=payload)
        return result.get('data', result)

    def get_client_group(self, group_uid):
        result = self._get(
            '/nfs/clientGroups/{uid}'.format(uid=group_uid))
        return result.get('data', result)

    def delete_client_group_rule(self, group_uid, rule_uid):
        return self._delete(
            '/nfs/clientGroups/{uid}/rules/{rule_uid}'.format(
                uid=group_uid, rule_uid=rule_uid))

    def delete_client_group(self, group_uid):
        """Delete a client group, removing its rules first.

        Weka rejects the delete while any rule remains.
        """
        try:
            cg = self.get_client_group(group_uid)
            for rule in cg.get('rules', []):
                rule_uid = rule.get('uid')
                if rule_uid:
                    try:
                        self.delete_client_group_rule(group_uid, rule_uid)
                    except Exception:
                        pass
        except Exception:
            pass
        return self._delete(
            '/nfs/clientGroups/{uid}'.format(uid=group_uid))

    # CIDR Allow/Deny rules attached to a filesystem and enforced at
    # native mount time: once any policy is attached, an unmatched source
    # IP is denied, and read_only forces a read-only mount.  Policies are
    # organization-owned, so call these on an org-scoped client.

    def list_security_policies(self):
        result = self._get('/security/policies')
        return result.get('data', result)

    def get_security_policy_by_name(self, name):
        """Find a security policy by name; returns None if not found."""
        for pol in self.list_security_policies() or []:
            if pol.get('name') == name:
                return pol
        return None

    def create_security_policy(self, name, ips, action='Allow',
                               read_only=False):
        payload = {
            'name': name,
            'action': action,
            'ip': list(ips or []),
            'read_only': read_only,
        }
        result = self._post('/security/policies', json=payload)
        return result.get('data', result)

    def update_security_policy(self, policy_uid,
                               add_ips=None, remove_ips=None):
        """Add or remove addresses on a policy (PATCH /security/policies).

        Never send 'name': the API reads it as a rename and rejects the
        policy's own name with "already in use", which callers that
        tolerate already-exists errors swallow -- silently dropping every
        address change.
        """
        payload = {}
        if add_ips:
            payload['add_ip'] = list(add_ips)
        if remove_ips:
            payload['remove_ip'] = list(remove_ips)
        result = self._patch(
            '/security/policies/{uid}'.format(uid=policy_uid), json=payload)
        return result.get('data', result)

    def delete_security_policy(self, policy_uid):
        return self._delete(
            '/security/policies/{uid}'.format(uid=policy_uid))

    def get_fs_security_policies(self, fs_uid):
        result = self._get(
            '/fileSystems/{uid}/securityPolicy'.format(uid=fs_uid))
        return result.get('data', result)

    def attach_fs_security_policies(self, fs_uid, policy_uids):
        result = self._post(
            '/fileSystems/{uid}/securityPolicy/attach'.format(uid=fs_uid),
            json={'policies': list(policy_uids)})
        return result.get('data', result)

    def detach_fs_security_policies(self, fs_uid, policy_uids):
        result = self._post(
            '/fileSystems/{uid}/securityPolicy/detach'.format(uid=fs_uid),
            json={'policies': list(policy_uids)})
        return result.get('data', result)

    def list_snapshots(self, fs_uid=None):
        """Return all snapshots; any fs_uid filter is applied locally."""
        result = self._get('/snapshots')
        snaps = result.get('data', result)
        if fs_uid is not None:
            snaps = [s for s in snaps
                     if s.get('filesystemUid') == fs_uid]
        return snaps

    def get_snapshot(self, snap_uid):
        result = self._get('/snapshots/{uid}'.format(uid=snap_uid))
        return result.get('data', result)

    def get_snapshot_by_name(self, name, fs_uid=None):
        """Find a snapshot by name; returns None if not found."""
        for snap in self.list_snapshots(fs_uid=fs_uid):
            if snap.get('name') == name:
                return snap
        return None

    def create_snapshot(self, fs_uid, name, is_writable=False):
        payload = {
            'fs_uid': fs_uid,
            'name': name,
            'is_writable': is_writable,
        }
        result = self._post('/snapshots', json=payload)
        return result.get('data', result)

    def delete_snapshot(self, snap_uid):
        return self._delete('/snapshots/{uid}'.format(uid=snap_uid))

    def restore_snapshot(self, snap_uid, fs_uid):
        """Revert a filesystem to a snapshot (POST .../{fs}/{uid}/restore)."""
        result = self._post(
            '/snapshots/{fs_uid}/{uid}/restore'.format(
                fs_uid=fs_uid, uid=snap_uid))
        return result.get('data', result)

    def get_capacity(self):
        """Return {totalBytes, usedBytes} for the cluster.

        GET /capacity on Weka 4.x, summed from GET /drives on 5.x.
        """
        try:
            result = self._get('/capacity')
            return result.get('data', result)
        except Exception:
            pass

        # Weka 5.x fallback: compute from individual drives
        drives_result = self._get('/drives')
        drives = drives_result.get('data', drives_result)
        if not isinstance(drives, list):
            return {}
        total_bytes = sum(d.get('size_bytes', 0) for d in drives)
        used_bytes = sum(
            int(d.get('size_bytes', 0) * d.get('percentage_used', 0) / 100)
            for d in drives
        )
        return {'totalBytes': total_bytes, 'usedBytes': used_bytes}
