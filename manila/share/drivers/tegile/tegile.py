# Copyright (c) 2016 by Tegile Systems, Inc.
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
Share driver for Tegile storage.
"""

import json
import requests
import six

from oslo_config import cfg
from oslo_log import log

from manila import utils
from manila.i18n import _, _LI, _LW
from manila import exception
from manila.share import driver
from manila.share import utils as share_utils

tegile_opts = [
    cfg.StrOpt('tegile_nas_server',
               help='Tegile NAS server hostname or IP address.'),
    cfg.StrOpt('tegile_nas_login',
               help='User name for the Tegile NAS server.'),
    cfg.StrOpt('tegile_nas_password',
               help='Password for the Tegile NAS server.'),
    cfg.StrOpt('tegile_default_project',
               help='Create shares in this project')]


CONF = cfg.CONF
CONF.register_opts(tegile_opts)

LOG = log.getLogger(__name__)
DEFAULT_API_SERVICE = 'openstack'
TEGILE_API_PATH = 'zebi/api'
TEGILE_LOCAL_CONTAINER_NAME = 'Local'
TEGILE_SNAPSHOT_PREFIX = 'Manual-S-'
VENDOR = 'Tegile Systems Inc.'
DEFAULT_BACKEND_NAME = 'Tegile'
VERSION = '1.0.0'
DEBUG_LOGGING = False  # For debugging purposes


def debugger(func):
    """Returns a wrapper that wraps func.

    The wrapper will log the entry and exit points of the function.
    """

    def wrapper(*args, **kwds):
        if DEBUG_LOGGING:
            LOG.debug('Entering %(classname)s.%(funcname)s',
                      {
                          'classname': args[0].__class__.__name__,
                          'funcname': func.__name__,
                      })
            LOG.debug('Arguments: %(args)s, %(kwds)s',
                      {
                          'args': args[1:],
                          'kwds': kwds,
                      })
        f_result = func(*args, **kwds)
        if DEBUG_LOGGING:
            LOG.debug('Exiting %(classname)s.%(funcname)s',
                      {
                          'classname': args[0].__class__.__name__,
                          'funcname': func.__name__,
                      })
            LOG.debug('Results: %(result)s',
                      {'result': f_result})
        return f_result

    return wrapper


class TegileAPIExecutor(object):
    def __init__(self, classname, hostname, username, password):
        self._classname = classname
        self._hostname = hostname
        self._username = username
        self._password = password

    def __call__(self, *args, **kwargs):
        return self._send_api_request(*args, **kwargs)

    @debugger
    @utils.retry(exception=(requests.ConnectionError, requests.Timeout),
                 interval=30,
                 retries=3,
                 backoff_rate=1)
    def _send_api_request(self, method, params=None,
                          request_type='post',
                          api_service=DEFAULT_API_SERVICE,
                          fine_logging=DEBUG_LOGGING):
        if params is not None:
            params = json.dumps(params)

        url = 'https://%s/%s/%s/%s' % (self._hostname,
                                       TEGILE_API_PATH,
                                       api_service,
                                       method)
        if fine_logging:
            LOG.debug('TegileAPIExecutor(%(classname)s) method: %(method)s, '
                      'url: %(url)s', {
                          'classname': self._classname,
                          'method': method,
                          'url': url,
                      })
        if request_type == 'post':
            if fine_logging:
                LOG.debug('TegileAPIExecutor(%(classname)s) '
                          'method: %(method)s, payload: %(payload)s',
                          {
                              'classname': self._classname,
                              'method': method,
                              'payload': params,
                          })
            req = requests.post(url,
                                data=params,
                                auth=(self._username, self._password),
                                verify=False)
        else:
            req = requests.get(url,
                               auth=(self._username, self._password),
                               verify=False)

        if fine_logging:
            LOG.debug('TegileAPIExecutor(%(classname)s) method: %(method)s, '
                      'return code: %(retcode)s',
                      {
                          'classname': self._classname,
                          'method': method,
                          'retcode': req,
                      })
        try:
            response = req.json()
            if fine_logging:
                LOG.debug('TegileAPIExecutor(%(classname)s) '
                          'method: %(method)s, response: %(response)s',
                          {
                              'classname': self._classname,
                              'method': method,
                              'response': response,
                          })
        except ValueError:
            # Some APIs don't return output and that's fine
            response = ''
        req.close()

        if req.status_code != 200:
            raise exception.TegileAPIException(response=req.text)

        return response


class TegileShareDriver(driver.ShareDriver):
    """Tegile NAS driver. Allows for NFS and CIFS NAS storage usage."""
    def __init__(self, *args, **kwargs):
        super(TegileShareDriver, self).__init__(False, *args, **kwargs)

        self.configuration.append_config_values(tegile_opts)
        self._default_project = (self.configuration.safe_get(
            "tegile_default_project") or 'openstack')
        self._backend_name = (self.configuration.safe_get('share_backend_name')
                              or CONF.share_backend_name
                              or DEFAULT_BACKEND_NAME)
        self._hostname = self.configuration.safe_get('tegile_nas_server')
        username = self.configuration.safe_get('tegile_nas_login')
        password = self.configuration.safe_get('tegile_nas_password')
        self._api = TegileAPIExecutor(self.__class__.__name__,
                                      self._hostname,
                                      username,
                                      password)

    @debugger
    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        share_name = share['name']
        share_proto = share['share_proto']

        pool_name = share_utils.extract_host(share['host'], level='pool')

        params = (pool_name, self._default_project, share_name, share_proto)

        # Share name coming from the backend is the most reliable. Sometimes
        # a few options in Tegile array could cause sharename to be different
        # from the one passed to it. Eg. 'projectname-sharename' instead
        # of 'sharename' if inherited share properties are selected.
        ip, real_share_name = self._api('createShare', params).split()

        LOG.info(_LI("Created share %(sharename)s, share id %(shid)s."),
                 {'sharename': share_name, 'shid': share['id']})

        return self._get_location_path(real_share_name, share_proto, ip)

    @debugger
    def extend_share(self, share, new_size, share_server=None):
        """Is called to extend share.

        There is no resize for Tegile shares.
        We just adjust the quotas. The API is still called 'resizeShare'.
        """

        self._adjust_size(share, new_size, share_server)

    @debugger
    def shrink_share(self, shrink_share, shrink_size, share_server=None):
        """Uses resize_share to shrink a share.

        There is no shrink for Tegile shares.
        We just adjust the quotas. The API is still called 'resizeShare'.
        """
        self._adjust_size(shrink_share, shrink_size, share_server)

    @debugger
    def _adjust_size(self, share, new_size, share_server=None):
        pool, project, share_name = self._get_pool_project_share_name(share)
        params = ('%s/%s/%s/%s' % (pool,
                                   TEGILE_LOCAL_CONTAINER_NAME,
                                   project,
                                   share_name),
                  six.text_type(new_size),
                  'GB')
        self._api('resizeShare', params)

    @debugger
    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        pool, project, share_name = self._get_pool_project_share_name(share)
        params = ('%s/%s/%s/%s' % (pool,
                                   TEGILE_LOCAL_CONTAINER_NAME,
                                   project,
                                   share_name),
                  True,
                  False)

        self._api('deleteShare', params)

    @debugger
    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        snap_name = snapshot['name']

        pool, project, share_name = self._get_pool_project_share_name(
            snapshot['share'])

        share = {
            'poolName': '%s' % pool,
            'projectName': '%s' % project,
            'name': share_name,
            'availableSize': 0,
            'totalSize': 0,
            'datasetPath': '%s/%s/%s' %
                           (pool,
                            TEGILE_LOCAL_CONTAINER_NAME,
                            project),
            'mountpoint': share_name,
            'local': 'true',
        }

        params = (share, snap_name, False)

        LOG.info(_LI('Creating snapshot for share_name=%(shr)s'
                     ' snap_name=%(name)s'),
                 {'shr': share_name, 'name': snap_name})

        self._api('createShareSnapshot', params)

    @debugger
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Create a share from a snapshot - clone a snapshot."""
        pool, project, share_name = self._get_pool_project_share_name(share)

        params = ('%s/%s/%s/%s@%s%s' % (pool,
                                        TEGILE_LOCAL_CONTAINER_NAME,
                                        project,
                                        snapshot['share_name'],
                                        TEGILE_SNAPSHOT_PREFIX,
                                        snapshot['name'],
                                        ),
                  share_name,
                  True,
                  )

        ip, real_share_name = self._api('cloneShareSnapshot',
                                        params).split()

        share_proto = share['share_proto']
        return self._get_location_path(real_share_name, share_proto, ip)

    @debugger
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        pool, project, share_name = self._get_pool_project_share_name(
            snapshot['share'])
        params = ('%s/%s/%s/%s@%s%s' % (pool,
                                        TEGILE_LOCAL_CONTAINER_NAME,
                                        project,
                                        share_name,
                                        TEGILE_SNAPSHOT_PREFIX,
                                        snapshot['name']),
                  False)

        self._api('deleteShareSnapshot', params)

    @debugger
    def ensure_share(self, context, share, share_server=None):
        """Invoked to sure that share is exported."""

        # Fetching share name from server, because some configuration
        # options can cause sharename different from the OpenStack share name
        pool, project, share_name = self._get_pool_project_share_name(share)
        params = [
            '%s/%s/%s/%s' % (pool,
                             TEGILE_LOCAL_CONTAINER_NAME,
                             project,
                             share_name),
        ]
        ip, real_share_name = self._api('getShareIPAndMountPoint',
                                        params).split()

        share_proto = share['share_proto']
        location = self._get_location_path(real_share_name, share_proto, ip)
        return [location]

    @debugger
    def _allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        share_proto = share['share_proto']
        access_type = access['access_type']
        access_level = access['access_level']
        access_to = access['access_to']

        self._check_share_access(share_proto, access_type)

        pool, project, share_name = self._get_pool_project_share_name(share)
        params = ('%s/%s/%s/%s' % (pool,
                                   TEGILE_LOCAL_CONTAINER_NAME,
                                   project,
                                   share_name),
                  share_proto,
                  access_type,
                  access_to,
                  access_level)

        self._api('shareAllowAccess', params)

    @debugger
    def _deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        share_proto = share['share_proto']
        access_type = access['access_type']
        access_level = access['access_level']
        access_to = access['access_to']

        self._check_share_access(share_proto, access_type)

        pool, project, share_name = self._get_pool_project_share_name(share)
        params = ('%s/%s/%s/%s' % (pool,
                                   TEGILE_LOCAL_CONTAINER_NAME,
                                   project,
                                   share_name),
                  share_proto,
                  access_type,
                  access_to,
                  access_level)

        self._api('shareDenyAccess', params)

    def _check_share_access(self, share_proto, access_type):
        if share_proto == 'CIFS' and access_type != 'user':
            reason = _LW('Only USER access type is allowed for '
                         'CIFS shares.')
            LOG.warning(reason)
            raise exception.InvalidShareAccess(reason=reason)
        elif share_proto == 'NFS' and access_type not in ('ip', 'user'):
            reason = _LW('Only IP or USER access types are allowed for '
                         'NFS shares.')
            LOG.warning(reason)
            raise exception.InvalidShareAccess(reason=reason)
        elif share_proto not in ('NFS', 'CIFS'):
            reason = _LW('Unsupported protocol \"%s\" specified for '
                         'access rule.') % share_proto
            raise exception.InvalidShareAccess(reason=reason)

    @debugger
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        if not (add_rules or delete_rules):
            # Recovery mode
            pool, project, share_name = (
                self._get_pool_project_share_name(share))
            share_proto = share['share_proto']
            params = ('%s/%s/%s/%s' % (pool,
                                       TEGILE_LOCAL_CONTAINER_NAME,
                                       project,
                                       share_name),
                      share_proto)

            # Clears all current ACLs
            # Remove ip and user ACLs if share_proto is NFS
            # Remove user ACLs if share_proto is CIFS
            self._api('clearAccessRules', params)

            # Looping thru all rules.
            # Will have one API call per rule.
            for access in access_rules:
                self._allow_access(context, share, access, share_server)
        else:
            # Adding/Deleting specific rules
            for access in delete_rules:
                self._deny_access(context, share, access, share_server)
            for access in add_rules:
                self._allow_access(context, share, access, share_server)

    @debugger
    def _update_share_stats(self, **kwargs):
        """Retrieve stats info."""

        try:
            data = self._api(method='getArrayStats',
                             request_type='get',
                             fine_logging=False)
            # fixing values coming back here as String to float
            for pool in data.get('pools', []):
                pool['total_capacity_gb'] = float(
                    pool.get('total_capacity_gb', 0))
                pool['free_capacity_gb'] = float(
                    pool.get('free_capacity_gb', 0))
                pool['allocated_capacity_gb'] = float(
                    pool.get('allocated_capacity_gb', 0))

                pool['qos'] = pool.pop('QoS_support', False)
                pool['reserved_percentage'] = (
                    self.configuration.reserved_share_percentage)
                pool['dedupe'] = True
                pool['compression'] = True
                pool['thin_provisioning'] = True
                pool['max_over_subscription_ratio'] = (
                    self.configuration.max_over_subscription_ratio)

            data['share_backend_name'] = self._backend_name
            data['vendor_name'] = VENDOR
            data['driver_version'] = VERSION
            data['storage_protocol'] = 'NFS_CIFS'
            data['snapshot_support'] = True
            data['qos'] = False

            super(TegileShareDriver, self)._update_share_stats(data)
        except Exception as e:
            msg = _('Unexpected error while trying to get the '
                    'usage stats from array.')
            LOG.exception(msg)
            raise e

    @debugger
    def get_pool(self, share):
        """Returns pool name where share resides.

        :param share: The share hosted by the driver.
        :return: Name of the pool where given share is hosted.
        """
        pool = share_utils.extract_host(share['host'], level='pool')
        return pool

    @debugger
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return 0

    @debugger
    def _get_location_path(self, share_name, share_proto, ip=None):
        if ip is None:
            ip = self._hostname
        if share_proto == 'NFS':
            location = '%s:%s' % (ip, share_name)
        elif share_proto == 'CIFS':
            location = r'\\%s\%s' % (ip, share_name)
        else:
            message = _('Invalid NAS protocol supplied: %s.') % share_proto
            raise exception.InvalidInput(message)

        export_location = {
            'path': location,
            'is_admin_only': False,
            'metadata': {
                'preferred': True,
            },
        }
        return export_location

    @debugger
    def _get_pool_project_share_name(self, share):
        pool = share_utils.extract_host(share['host'], level='pool')
        project = self._default_project

        share_name = share['name']

        return pool, project, share_name
