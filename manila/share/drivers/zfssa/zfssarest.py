# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
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
ZFS Storage Appliance Proxy
"""
from oslo_log import log
from oslo_serialization import jsonutils

from manila import exception
from manila.i18n import _
from manila.share.drivers.zfssa import restclient


LOG = log.getLogger(__name__)


def factory_restclient(url, logfunc, **kwargs):
    return restclient.RestClientURL(url, logfunc, **kwargs)


class ZFSSAApi(object):
    """ZFSSA API proxy class."""
    pools_path = '/api/storage/v1/pools'
    pool_path = pools_path + '/%s'
    projects_path = pool_path + '/projects'
    project_path = projects_path + '/%s'
    shares_path = project_path + '/filesystems'
    share_path = shares_path + '/%s'
    snapshots_path = share_path + '/snapshots'
    snapshot_path = snapshots_path + '/%s'
    clone_path = snapshot_path + '/clone'
    service_path = '/api/service/v1/services/%s/enable'

    def __init__(self):
        self.host = None
        self.url = None
        self.rclient = None

    def __del__(self):
        if self.rclient:
            del self.rclient

    def rest_get(self, path, expected):
        ret = self.rclient.get(path)
        if ret.status != expected:
            exception_msg = (_('Rest call to %(host)s %(path)s failed.'
                               'Status: %(status)d Message: %(data)s')
                             % {'host': self.host,
                                'path': path,
                                'status': ret.status,
                                'data': ret.data})
            LOG.error(exception_msg)
            raise exception.ShareBackendException(msg=exception_msg)
        return ret

    def _is_pool_owned(self, pdata):
        """returns True if the pool's owner is the same as the host."""
        svc = '/api/system/v1/version'
        ret = self.rest_get(svc, restclient.Status.OK)
        vdata = jsonutils.loads(ret.data)
        return (vdata['version']['asn'] == pdata['pool']['asn'] and
                vdata['version']['nodename'] == pdata['pool']['owner'])

    def set_host(self, host, timeout=None):
        self.host = host
        self.url = "https://%s:215" % self.host
        self.rclient = factory_restclient(self.url, LOG.debug, timeout=timeout)

    def login(self, auth_str):
        """Login to the appliance."""
        if self.rclient and not self.rclient.islogin():
            self.rclient.login(auth_str)

    def enable_service(self, service):
        """Enable the specified service."""
        svc = self.service_path % service
        ret = self.rclient.put(svc)
        if ret.status != restclient.Status.ACCEPTED:
            exception_msg = (_("Cannot enable %s service.") % service)
            raise exception.ShareBackendException(msg=exception_msg)

    def verify_avail_space(self, pool, project, share, size):
        """Check if there is enough space available to a new share."""
        self.verify_project(pool, project)
        avail = self.get_project_stats(pool, project)
        if avail < size:
            exception_msg = (_('Error creating '
                               'share: %(share)s on '
                               'pool: %(pool)s. '
                               'Not enough space.')
                             % {'share': share,
                                'pool': pool})
            raise exception.ShareBackendException(msg=exception_msg)

    def get_pool_stats(self, pool):
        """Get space_available and used properties of a pool.

           returns (avail, used).
        """
        svc = self.pool_path % pool
        ret = self.rclient.get(svc)
        if ret.status != restclient.Status.OK:
            exception_msg = (_('Error getting pool stats: '
                               'pool: %(pool)s '
                               'return code: %(ret.status)d '
                               'message: %(ret.data)s.')
                             % {'pool': pool,
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            raise exception.InvalidInput(reason=exception_msg)
        val = jsonutils.loads(ret.data)
        if not self._is_pool_owned(val):
            exception_msg = (_('Error pool ownership: '
                               'pool %(pool)s is not owned '
                               'by %(host)s.')
                             % {'pool': pool,
                                'host': self.host})
            raise exception.InvalidInput(reason=pool)
        avail = val['pool']['usage']['available']
        used = val['pool']['usage']['used']
        return avail, used

    def get_project_stats(self, pool, project):
        """Get space_available of a project.

           Used to check whether a project has enough space (after reservation)
           or not.
        """
        svc = self.project_path % (pool, project)
        ret = self.rclient.get(svc)
        if ret.status != restclient.Status.OK:
            exception_msg = (_('Error getting project stats: '
                               'pool: %(pool)s '
                               'project: %(project)s '
                               'return code: %(ret.status)d '
                               'message: %(ret.data)s.')
                             % {'pool': pool,
                                'project': project,
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            raise exception.InvalidInput(reason=exception_msg)
        val = jsonutils.loads(ret.data)
        avail = val['project']['space_available']
        return avail

    def create_project(self, pool, project, arg):
        """Create a project on a pool. Check first whether the pool exists."""
        self.verify_pool(pool)
        svc = self.project_path % (pool, project)
        ret = self.rclient.get(svc)
        if ret.status != restclient.Status.OK:
            svc = self.projects_path % pool
            ret = self.rclient.post(svc, arg)
            if ret.status != restclient.Status.CREATED:
                exception_msg = (_('Error creating project: '
                                   '%(project)s on '
                                   'pool: %(pool)s '
                                   'return code: %(ret.status)d '
                                   'message: %(ret.data)s.')
                                 % {'project': project,
                                    'pool': pool,
                                    'ret.status': ret.status,
                                    'ret.data': ret.data})
                raise exception.ShareBackendException(msg=exception_msg)

    def verify_pool(self, pool):
        """Checks whether pool exists."""
        svc = self.pool_path % pool
        self.rest_get(svc, restclient.Status.OK)

    def verify_project(self, pool, project):
        """Checks whether project exists."""
        svc = self.project_path % (pool, project)
        ret = self.rest_get(svc, restclient.Status.OK)
        return ret

    def create_share(self, pool, project, share):
        """Create a share in the specified pool and project."""
        self.verify_avail_space(pool, project, share, share['quota'])
        svc = self.share_path % (pool, project, share['name'])
        ret = self.rclient.get(svc)
        if ret.status != restclient.Status.OK:
            svc = self.shares_path % (pool, project)
            ret = self.rclient.post(svc, share)
            if ret.status != restclient.Status.CREATED:
                exception_msg = (_('Error creating '
                                   'share: %(name)s '
                                   'return code: %(ret.status)d '
                                   'message: %(ret.data)s.')
                                 % {'name': share['name'],
                                    'ret.status': ret.status,
                                    'ret.data': ret.data})
                raise exception.ShareBackendException(msg=exception_msg)
        else:
            exception_msg = (_('Share with name %s already exists.')
                             % share['name'])
            raise exception.ShareBackendException(msg=exception_msg)

    def get_share(self, pool, project, share):
        """Return share properties."""
        svc = self.share_path % (pool, project, share)
        ret = self.rest_get(svc, restclient.Status.OK)
        val = jsonutils.loads(ret.data)
        return val['filesystem']

    def modify_share(self, pool, project, share, arg):
        """Modify a set of properties of a share."""
        svc = self.share_path % (pool, project, share)
        ret = self.rclient.put(svc, arg)
        if ret.status != restclient.Status.ACCEPTED:
            exception_msg = (_('Error modifying %(arg)s '
                               ' of share %(id)s.')
                             % {'arg': arg,
                                'id': share})
            raise exception.ShareBackendException(msg=exception_msg)

    def delete_share(self, pool, project, share):
        """Delete a share.

        The function assumes the share has no clone or snapshot.
        """
        svc = self.share_path % (pool, project, share)
        ret = self.rclient.delete(svc)
        if ret.status != restclient.Status.NO_CONTENT:
            exception_msg = (('Error deleting '
                              'share: %(share)s to '
                              'pool: %(pool)s '
                              'project: %(project)s '
                              'return code: %(ret.status)d '
                              'message: %(ret.data)s.'),
                             {'share': share,
                              'pool': pool,
                              'project': project,
                              'ret.status': ret.status,
                              'ret.data': ret.data})
            LOG.error(exception_msg)

    def create_snapshot(self, pool, project, share, snapshot):
        """Create a snapshot of the given share."""
        svc = self.snapshots_path % (pool, project, share)
        arg = {'name': snapshot}
        ret = self.rclient.post(svc, arg)
        if ret.status != restclient.Status.CREATED:
            exception_msg = (_('Error creating '
                               'snapshot: %(snapshot)s on '
                               'share: %(share)s to '
                               'pool: %(pool)s '
                               'project: %(project)s '
                               'return code: %(ret.status)d '
                               'message: %(ret.data)s.')
                             % {'snapshot': snapshot,
                                'share': share,
                                'pool': pool,
                                'project': project,
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            raise exception.ShareBackendException(msg=exception_msg)

    def delete_snapshot(self, pool, project, share, snapshot):
        """Delete a snapshot that has no clone."""
        svc = self.snapshot_path % (pool, project, share, snapshot)
        ret = self.rclient.delete(svc)
        if ret.status != restclient.Status.NO_CONTENT:
            exception_msg = (_('Error deleting '
                               'snapshot: %(snapshot)s on '
                               'share: %(share)s to '
                               'pool: %(pool)s '
                               'project: %(project)s  '
                               'return code: %(ret.status)d '
                               'message: %(ret.data)s.')
                             % {'snapshot': snapshot,
                                'share': share,
                                'pool': pool,
                                'project': project,
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            LOG.error(exception_msg)
            raise exception.ShareBackendException(msg=exception_msg)

    def clone_snapshot(self, pool, project, snapshot, clone, arg):
        """Create a new share from the given snapshot."""
        self.verify_avail_space(pool, project, clone['id'], clone['size'])
        svc = self.clone_path % (pool, project,
                                 snapshot['share_id'],
                                 snapshot['id'])
        ret = self.rclient.put(svc, arg)
        if ret.status != restclient.Status.CREATED:
            exception_msg = (_('Error cloning '
                               'snapshot: %(snapshot)s on '
                               'share: %(share)s of '
                               'Pool: %(pool)s '
                               'project: %(project)s '
                               'return code: %(ret.status)d '
                               'message: %(ret.data)s.')
                             % {'snapshot': snapshot['id'],
                                'share': snapshot['share_id'],
                                'pool': pool,
                                'project': project,
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            LOG.error(exception_msg)
            raise exception.ShareBackendException(msg=exception_msg)

    def has_clones(self, pool, project, share, snapshot):
        """Check whether snapshot has existing clones."""
        svc = self.snapshot_path % (pool, project, share, snapshot)
        ret = self.rest_get(svc, restclient.Status.OK)
        val = jsonutils.loads(ret.data)
        return val['snapshot']['numclones'] != 0

    def allow_access_nfs(self, pool, project, share, access):
        """Allow an IP access to a share through NFS."""
        if access['access_type'] != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason)

        ip = access['access_to']
        details = self.get_share(pool, project, share)
        sharenfs = details['sharenfs']

        if sharenfs == 'on' or sharenfs == 'rw':
            LOG.debug('Share %s has read/write permission'
                      'open to all.', share)
            return
        if sharenfs == 'off':
            sharenfs = 'sec=sys'
        if ip in sharenfs:
            LOG.debug('Access to share %(share)s via NFS '
                      'already granted to %(ip)s.',
                      {'share': share,
                       'ip': ip})
            return

        entry = (',rw=@%s' % ip)
        if '/' not in ip:
            entry = "%s/32" % entry
        arg = {'sharenfs': sharenfs + entry}
        self.modify_share(pool, project, share, arg)

    def deny_access_nfs(self, pool, project, share, access):
        """Denies access of an IP to a share through NFS.

        Since sharenfs property allows a combination of mutiple syntaxes:
        sharenfs="sec=sys,rw=@first_ip,rw=@second_ip"
        sharenfs="sec=sys,rw=@first_ip:@second_ip"
        sharenfs="sec=sys,rw=@first_ip:@second_ip,rw=@third_ip"
        The function checks what syntax is used and remove the IP accordingly.
        """
        if access['access_type'] != 'ip':
            reason = _('Only ip access type allowed.')
            raise exception.InvalidShareAccess(reason)

        ip = access['access_to']
        entry = ('@%s' % ip)
        if '/' not in ip:
            entry = "%s/32" % entry
        details = self.get_share(pool, project, share)
        if entry not in details['sharenfs']:
            LOG.debug('IP %(ip)s does not have access '
                      'to Share %(share)s via NFS.',
                      {'ip': ip,
                       'share': share})
            return

        sharenfs = str(details['sharenfs'])
        argval = ''
        if sharenfs.find((',rw=%s:' % entry)) >= 0:
            argval = sharenfs.replace(('%s:' % entry), '')
        elif sharenfs.find((',rw=%s' % entry)) >= 0:
            argval = sharenfs.replace((',rw=%s' % entry), '')
        elif sharenfs.find((':%s' % entry)) >= 0:
            argval = sharenfs.replace((':%s' % entry), '')
        arg = {'sharenfs': argval}
        LOG.debug('deny_access: %s', argval)
        self.modify_share(pool, project, share, arg)

    def create_schema(self, schema):
        """Create a custom ZFSSA schema."""
        base = '/api/storage/v1/schema'
        svc = "%(base)s/%(prop)s" % {'base': base, 'prop': schema['property']}
        ret = self.rclient.get(svc)
        if ret.status == restclient.Status.OK:
            LOG.warning('Property %s already exists.', schema['property'])
            return
        ret = self.rclient.post(base, schema)
        if ret.status != restclient.Status.CREATED:
            exception_msg = (_('Error Creating '
                               'Property: %(property)s '
                               'Type: %(type)s '
                               'Description: %(description)s '
                               'Return code: %(ret.status)d '
                               'Message: %(ret.data)s.')
                             % {'property': schema['property'],
                                'type': schema['type'],
                                'description': schema['description'],
                                'ret.status': ret.status,
                                'ret.data': ret.data})
            LOG.error(exception_msg)
            raise exception.ShareBackendException(msg=exception_msg)
