# Copyright 2015 Hewlett Packard Development Company, L.P.
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

"""HP 3PAR Mediator for OpenStack Manila.

This 'mediator' de-couples the 3PAR focused client from the OpenStack focused
driver.
"""

from oslo_log import log
from oslo_utils import importutils
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _, _LI

hp3parclient = importutils.try_import("hp3parclient")
if hp3parclient:
    from hp3parclient import file_client


LOG = log.getLogger(__name__)
MIN_CLIENT_VERSION = (3, 2, 1)
DENY = '-'
ALLOW = '+'
OPEN_STACK_MANILA_FSHARE = 'OpenStack Manila fshare'


class HP3ParMediator(object):

    VERSION = "1.0.00"

    def __init__(self, **kwargs):

        self.hp3par_username = kwargs.get('hp3par_username')
        self.hp3par_password = kwargs.get('hp3par_password')
        self.hp3par_api_url = kwargs.get('hp3par_api_url')
        self.hp3par_debug = kwargs.get('hp3par_debug')
        self.hp3par_san_ip = kwargs.get('hp3par_san_ip')
        self.hp3par_san_login = kwargs.get('hp3par_san_login')
        self.hp3par_san_password = kwargs.get('hp3par_san_password')
        self.hp3par_san_ssh_port = kwargs.get('hp3par_san_ssh_port')
        self.hp3par_san_private_key = kwargs.get('hp3par_san_private_key')
        self.hp3par_fstore_per_share = kwargs.get('hp3par_fstore_per_share')

        self.ssh_conn_timeout = kwargs.get('ssh_conn_timeout')
        self._client = None

    @staticmethod
    def no_client():
        return hp3parclient is None

    def do_setup(self):

        if self.no_client():
            msg = _('You must install hp3parclient before using the 3PAR '
                    'driver.')
            LOG.exception(msg)
            raise exception.HP3ParInvalidClient(message=msg)

        client_version = hp3parclient.version_tuple
        if client_version < MIN_CLIENT_VERSION:
            msg = (_('Invalid hp3parclient version found (%(found)s). '
                     'Version %(minimum)s or greater required.') %
                   {'found': '.'.join(map(six.text_type, client_version)),
                    'minimum': '.'.join(map(six.text_type,
                                            MIN_CLIENT_VERSION))})
            LOG.exception(msg)
            raise exception.HP3ParInvalidClient(message=msg)

        try:
            self._client = file_client.HP3ParFilePersonaClient(
                self.hp3par_api_url)
        except Exception as e:
            msg = (_('Failed to connect to HP 3PAR File Persona Client: %s') %
                   six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        try:
            ssh_kwargs = {}
            if self.hp3par_san_ssh_port:
                ssh_kwargs['port'] = self.hp3par_san_ssh_port
            if self.ssh_conn_timeout:
                ssh_kwargs['conn_timeout'] = self.ssh_conn_timeout
            if self.hp3par_san_private_key:
                ssh_kwargs['privatekey'] = self.hp3par_san_private_key

            self._client.setSSHOptions(
                self.hp3par_san_ip,
                self.hp3par_san_login,
                self.hp3par_san_password,
                **ssh_kwargs
            )

        except Exception as e:
            msg = (_('Failed to set SSH options for HP 3PAR File Persona '
                     'Client: %s') % six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        LOG.info(_LI("HP3ParMediator %(version)s, "
                     "hp3parclient %(client_version)s"),
                 {"version": self.VERSION,
                  "client_version": hp3parclient.get_version_string()})

        try:
            wsapi_version = self._client.getWsApiVersion()['build']
            LOG.info(_LI("3PAR WSAPI %s"), wsapi_version)
        except Exception as e:
            msg = (_('Failed to get 3PAR WSAPI version: %s') %
                   six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        if self.hp3par_debug:
            self._client.debug_rest(True)  # Includes SSH debug (setSSH above)

    def get_capacity(self, fpg):
        try:
            result = self._client.getfpg(fpg)
        except Exception as e:
            msg = (_('Failed to get capacity for fpg %(fpg)s: %(e)s') %
                   {'fpg': fpg, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        if result['total'] != 1:
            msg = (_('Failed to get capacity for fpg %s.') % fpg)
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)
        else:
            member = result['members'][0]
            total_capacity_gb = int(member['capacityKiB']) / units.Mi
            free_capacity_gb = int(member['availCapacityKiB']) / units.Mi
            return {
                'total_capacity_gb': total_capacity_gb,
                'free_capacity_gb': free_capacity_gb
            }

    @staticmethod
    def ensure_supported_protocol(share_proto):
        protocol = share_proto.lower()
        if protocol == 'cifs':
            protocol = 'smb'
        if protocol not in ['smb', 'nfs']:
            message = (_('Invalid protocol. Expected nfs or smb. Got %s.') %
                       protocol)
            LOG.exception(message)
            raise exception.InvalidInput(message)
        return protocol

    @staticmethod
    def other_protocol(share_proto):
        """Given 'nfs' or 'smb' (or equivalent) return the other one."""
        protocol = HP3ParMediator.ensure_supported_protocol(share_proto)
        return 'nfs' if protocol == 'smb' else 'smb'

    @staticmethod
    def ensure_prefix(uid, protocol=None):
        if uid.startswith('osf-'):
            return uid
        elif protocol:
            return 'osf-%s-%s' % (
                HP3ParMediator.ensure_supported_protocol(protocol), uid)
        else:
            return 'osf-%s' % uid

    def create_share(self, project_id, share_id, share_proto, fpg, vfs,
                     fstore=None, sharedir=None, readonly=False, size=None):
        """Create the share and return its path.

        This method can create a share when called by the driver or when
        called locally from create_share_from_snapshot().  The optional
        parameters allow re-use.

        :param project_id: The tenant ID.
        :param share_id: The share-id with or without osf- prefix.
        :param share_proto: The protocol (to map to smb or nfs)
        :param fpg: The file provisioning group
        :param vfs:  The virtual file system
        :param fstore:  (optional) The file store.  When provided, an existing
        file store is used.  Otherwise one is created.
        :param sharedir: (optional) Share directory.
        :param readonly: (optional) Create share as read-only.
        :param size: (optional) Size limit for file store if creating one.
        :return: share path string
        """

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id)

        if not fstore:
            if self.hp3par_fstore_per_share:
                fstore = share_name
            else:
                fstore = self.ensure_prefix(project_id, protocol)

            try:
                result = self._client.createfstore(
                    vfs, fstore, fpg=fpg,
                    comment='OpenStack Manila fstore')
                LOG.debug("createfstore result=%s", result)
            except Exception as e:
                msg = (_('Failed to create fstore %(fstore)s: %(e)s') %
                       {'fstore': fstore, 'e': six.text_type(e)})
                LOG.exception(msg)
                raise exception.ShareBackendException(msg)

            if size:
                if self.hp3par_fstore_per_share:
                    hcapacity = six.text_type(size * units.Ki)
                    scapacity = hcapacity
                else:
                    hard_size_mb = size * units.Ki
                    soft_size_mb = hard_size_mb
                    result = self._client.getfsquota(
                        fpg=fpg, vfs=vfs, fstore=fstore)
                    LOG.debug("getfsquota result=%s", result)
                    quotas = result['members']
                    if len(quotas) == 1:
                        hard_size_mb += int(quotas[0].get('hardBlock', '0'))
                        soft_size_mb += int(quotas[0].get('softBlock', '0'))
                    hcapacity = six.text_type(hard_size_mb)
                    scapacity = six.text_type(soft_size_mb)

                try:
                    result = self._client.setfsquota(
                        vfs, fpg=fpg, fstore=fstore,
                        scapacity=scapacity, hcapacity=hcapacity)
                    LOG.debug("setfsquota result=%s", result)
                except Exception as e:
                    msg = (_('Failed to setfsquota on %(fstore)s: %(e)s') %
                           {'fstore': fstore, 'e': six.text_type(e)})
                    LOG.exception(msg)
                    raise exception.ShareBackendException(msg)

        if not (sharedir or self.hp3par_fstore_per_share):
            sharedir = share_name

        try:
            if protocol == 'nfs':
                if readonly:
                    options = 'ro,no_root_squash,insecure'
                else:
                    options = 'rw,no_root_squash,insecure'

                result = self._client.createfshare(
                    protocol, vfs, share_name,
                    fpg=fpg, fstore=fstore, sharedir=sharedir,
                    clientip='127.0.0.1',
                    options=options,
                    comment=OPEN_STACK_MANILA_FSHARE)
            else:
                result = self._client.createfshare(
                    protocol, vfs, share_name,
                    fpg=fpg, fstore=fstore, sharedir=sharedir,
                    allowip='127.0.0.1',
                    comment=OPEN_STACK_MANILA_FSHARE)
            LOG.debug("createfshare result=%s", result)

        except Exception as e:
            msg = (_('Failed to create share %(share_name)s: %(e)s') %
                   {'share_name': share_name, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        try:
            result = self._client.getfshare(
                protocol, share_name,
                fpg=fpg, vfs=vfs, fstore=fstore)
            LOG.debug("getfshare result=%s", result)

        except Exception as e:
            msg = (_('Failed to get fshare %(share_name)s after creating it: '
                     '%(e)s') % {'share_name': share_name,
                                 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        if result['total'] != 1:
            msg = (_('Failed to get fshare %(share_name)s after creating it. '
                     'Expected to get 1 fshare.  Got %(total)s.') %
                   {'share_name': share_name, 'total': result['total']})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        if protocol == 'nfs':
            return result['members'][0]['sharePath']
        else:
            return result['members'][0]['shareName']

    def create_share_from_snapshot(self, share_id, share_proto,
                                   orig_project_id, orig_share_id, orig_proto,
                                   snapshot_id, fpg, vfs):

        protocol = self.ensure_supported_protocol(share_proto)
        snapshot_tag = self.ensure_prefix(snapshot_id)
        orig_share_name = self.ensure_prefix(orig_share_id)

        snapshot = self._find_fsnap(orig_project_id,
                                    orig_share_name,
                                    orig_proto,
                                    snapshot_tag,
                                    fpg,
                                    vfs)

        if not snapshot:
            msg = (_('Failed to create share from snapshot for '
                     'FPG/VFS/tag %(fpg)s/%(vfs)s/%(tag)s. '
                     'Snapshot not found.') %
                   {
                       'fpg': fpg,
                       'vfs': vfs,
                       'tag': snapshot_tag})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        fstore = snapshot['fstoreName']
        share_name = self.ensure_prefix(share_id)
        if fstore == orig_share_name:
            # No subdir for original share created with fstore_per_share
            sharedir = '.snapshot/%s' % snapshot['snapName']
        else:
            sharedir = '.snapshot/%s/%s' % (snapshot['snapName'],
                                            orig_share_name)

        return self.create_share(
            orig_project_id,
            share_name,
            protocol,
            fpg,
            vfs,
            fstore=fstore,
            sharedir=sharedir,
            readonly=True,
        )

    def delete_share(self, project_id, share_id, share_proto, fpg, vfs):

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id)
        fstore = self._find_fstore(project_id, share_name, protocol, fpg, vfs,
                                   allow_cross_protocol=True)

        if not fstore:
            # Share does not exist.
            return

        try:
            self._client.removefshare(protocol, vfs, share_name,
                                      fpg=fpg, fstore=fstore)
        except Exception as e:
            msg = (_('Failed to remove share %(share_name)s: %(e)s') %
                   {'share_name': share_name, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        if fstore == share_name:
            try:
                self._client.removefstore(vfs, fstore, fpg=fpg)
            except Exception as e:
                msg = (_('Failed to remove fstore %(fstore)s: %(e)s') %
                       {'fstore': fstore, 'e': six.text_type(e)})
                LOG.exception(msg)
                raise exception.ShareBackendException(message=msg)

    def get_vfs_name(self, fpg):
        return self.get_vfs(fpg)['vfsname']

    def get_vfs(self, fpg, vfs=None):
        """Get the VFS or raise an exception."""

        try:
            result = self._client.getvfs(fpg=fpg, vfs=vfs)
        except Exception as e:
            msg = (_('Exception during getvfs %(vfs)s: %(e)s') %
                   {'vfs': vfs, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        if result['total'] != 1:
            error_msg = result.get('message')
            if error_msg:
                message = (_('Error while validating FPG/VFS '
                             '(%(fpg)s/%(vfs)s): %(msg)s') %
                           {'fpg': fpg, 'vfs': vfs, 'msg': error_msg})
                LOG.error(message)
                raise exception.ShareBackendException(message)
            else:
                message = (_('Error while validating FPG/VFS '
                             '(%(fpg)s/%(vfs)s): Expected 1, '
                             'got %(total)s.') %
                           {'fpg': fpg, 'vfs': vfs,
                            'total': result['total']})

                LOG.error(message)
                raise exception.ShareBackendException(message)

        return result['members'][0]

    def create_snapshot(self, orig_project_id, orig_share_id, orig_share_proto,
                        snapshot_id, fpg, vfs):
        """Creates a snapshot of a share."""

        fshare = self._find_fshare(orig_project_id,
                                   orig_share_id,
                                   orig_share_proto,
                                   fpg,
                                   vfs)

        if not fshare:
            msg = (_('Failed to create snapshot for FPG/VFS/fshare '
                     '%(fpg)s/%(vfs)s/%(fshare)s: Failed to find fshare.') %
                   {'fpg': fpg, 'vfs': vfs, 'fshare': orig_share_id})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        sharedir = fshare.get('shareDir')
        if sharedir and sharedir.startswith('.snapshot'):
            msg = (_('Failed to create snapshot for FPG/VFS/fshare '
                     '%(fpg)s/%(vfs)s/%(fshare)s: Share is a read-only '
                     'share of an existing snapshot.') %
                   {'fpg': fpg, 'vfs': vfs, 'fshare': orig_share_id})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        fstore = fshare.get('fstoreName')
        snapshot_tag = self.ensure_prefix(snapshot_id)
        try:
            result = self._client.createfsnap(
                vfs, fstore, snapshot_tag, fpg=fpg)

            LOG.debug("createfsnap result=%s", result)

        except Exception as e:
            msg = (_('Failed to create snapshot for FPG/VFS/fstore '
                     '%(fpg)s/%(vfs)s/%(fstore)s: %(e)s') %
                   {'fpg': fpg, 'vfs': vfs, 'fstore': fstore,
                    'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

    def delete_snapshot(self, orig_project_id, orig_share_id, orig_proto,
                        snapshot_id, fpg, vfs):
        """Deletes a snapshot of a share."""

        snapshot_tag = self.ensure_prefix(snapshot_id)

        snapshot = self._find_fsnap(orig_project_id, orig_share_id, orig_proto,
                                    snapshot_tag, fpg, vfs)

        if not snapshot:
            return

        fstore = snapshot.get('fstoreName')

        for protocol in ('nfs', 'smb'):
            try:
                shares = self._client.getfshare(protocol,
                                                fpg=fpg,
                                                vfs=vfs,
                                                fstore=fstore)
            except Exception as e:
                msg = (_('Unexpected exception while getting share list. '
                         'Cannot delete snapshot without checking for '
                         'dependent shares first: %s') % six.text_type(e))
                LOG.exception(msg)
                raise exception.ShareBackendException(msg)

            for share in shares['members']:
                if protocol == 'nfs':
                    path = share['sharePath'][1:].split('/')
                    dot_snapshot_index = 3
                else:
                    if share['shareDir']:
                        path = share['shareDir'].split('/')
                    else:
                        path = None
                    dot_snapshot_index = 0

                snapshot_index = dot_snapshot_index + 1
                if path and len(path) > snapshot_index:
                    if (path[dot_snapshot_index] == '.snapshot' and
                            path[snapshot_index].endswith(snapshot_tag)):
                        msg = (_('Cannot delete snapshot because it has a '
                                 'dependent share.'))
                        raise exception.Invalid(msg)

        snapname = snapshot['snapName']
        try:
            result = self._client.removefsnap(
                vfs, fstore, snapname=snapname, fpg=fpg)

            LOG.debug("removefsnap result=%s", result)

        except Exception as e:
            msg = (_('Failed to delete snapshot for FPG/VFS/fstore/snapshot '
                     '%(fpg)s/%(vfs)s/%(fstore)s/%(snapname)s: %(e)s') %
                   {
                       'fpg': fpg,
                       'vfs': vfs,
                       'fstore': fstore,
                       'snapname': snapname,
                       'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        # Try to reclaim the space
        try:
            self._client.startfsnapclean(fpg, reclaimStrategy='maxspeed')
        except Exception as e:
            # Remove already happened so only log this.
            msg = (_('Unexpected exception calling startfsnapclean for FPG '
                     '%(fpg)s: %(e)s') % {'fpg': fpg, 'e': six.text_type(e)})
            LOG.exception(msg)

    @staticmethod
    def validate_access_type(protocol, access_type):

        if access_type not in ('ip', 'user'):
            msg = (_("Invalid access type.  Expected 'ip' or 'user'.  "
                     "Actual '%s'.") % access_type)
            LOG.exception(msg)
            raise exception.InvalidInput(msg)

        if protocol == 'nfs' and access_type != 'ip':
            msg = (_("Invalid NFS access type.  HP 3PAR NFS supports 'ip'. "
                     "Actual '%s'.") % access_type)
            LOG.exception(msg)
            raise exception.HP3ParInvalid(msg)

        return protocol

    def _change_access(self, plus_or_minus, project_id, share_id, share_proto,
                       access_type, access_to, fpg, vfs):
        """Allow or deny access to a share.

        Plus_or_minus character indicates add to allow list (+) or remove from
        allow list (-).
        """

        protocol = self.ensure_supported_protocol(share_proto)
        self.validate_access_type(protocol, access_type)

        share_name = self.ensure_prefix(share_id)
        fstore = self._find_fstore(project_id, share_id, protocol, fpg, vfs,
                                   allow_cross_protocol=True)

        try:
            if protocol == 'nfs':
                result = self._client.setfshare(
                    protocol, vfs, share_name, fpg=fpg, fstore=fstore,
                    clientip='%s%s' % (plus_or_minus, access_to))
            elif protocol == 'smb':
                if access_type == 'ip':
                    result = self._client.setfshare(
                        protocol, vfs, share_name, fpg=fpg, fstore=fstore,
                        allowip='%s%s' % (plus_or_minus, access_to))
                else:
                    access_str = 'fullcontrol'
                    perm = '%s%s:%s' % (plus_or_minus, access_to, access_str)
                    result = self._client.setfshare(protocol, vfs, share_name,
                                                    fpg=fpg, fstore=fstore,
                                                    allowperm=perm)
            else:
                msg = (_("Unexpected error:  After ensure_supported_protocol "
                         "only 'nfs' or 'smb' strings are allowed, but found: "
                         "%s.") % protocol)
                raise exception.HP3ParUnexpectedError(msg)

            LOG.debug("setfshare result=%s", result)
        except Exception as e:
            msg = (_('Failed to change (%(change)s) access to FPG/share '
                     '%(fpg)s/%(share)s to %(type)s %(to)s): %(e)s') %
                   {'change': plus_or_minus, 'fpg': fpg, 'share': share_name,
                    'type': access_type, 'to': access_to,
                    'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

    def _find_fstore(self, project_id, share_id, share_proto, fpg, vfs,
                     allow_cross_protocol=False):

        share = self._find_fshare(project_id, share_id, share_proto, fpg, vfs)

        if not share and allow_cross_protocol:
            share = self._find_fshare(project_id,
                                      share_id,
                                      self.other_protocol(share_proto),
                                      fpg,
                                      vfs)

        return share.get('fstoreName') if share else None

    def _find_fshare(self, project_id, share_id, share_proto, fpg, vfs):

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id)

        project_fstore = self.ensure_prefix(project_id, share_proto)
        search_order = [
            {'fpg': fpg, 'vfs': vfs, 'fstore': project_fstore},
            {'fpg': fpg, 'vfs': vfs, 'fstore': share_name},
            {'fpg': fpg},
            {}
        ]

        try:
            for search_params in search_order:
                result = self._client.getfshare(protocol, share_name,
                                                **search_params)
                shares = result.get('members', [])
                if len(shares) == 1:
                    return shares[0]
        except Exception as e:
            msg = (_('Unexpected exception while getting share list: %s') %
                   six.text_type(e))
            raise exception.ShareBackendException(msg)

    def _find_fsnap(self, project_id, share_id, orig_proto, snapshot_tag,
                    fpg, vfs):

        share_name = self.ensure_prefix(share_id)
        osf_project_id = self.ensure_prefix(project_id, orig_proto)
        pattern = '*_%s' % self.ensure_prefix(snapshot_tag)

        search_order = [
            {'pat': True, 'fpg': fpg, 'vfs': vfs, 'fstore': osf_project_id},
            {'pat': True, 'fpg': fpg, 'vfs': vfs, 'fstore': share_name},
            {'pat': True, 'fpg': fpg},
            {'pat': True},
        ]

        try:
            for search_params in search_order:
                result = self._client.getfsnap(pattern, **search_params)
                snapshots = result.get('members', [])
                if len(snapshots) == 1:
                    return snapshots[0]
        except Exception as e:
            msg = (_('Unexpected exception while getting snapshots: %s') %
                   six.text_type(e))
            raise exception.ShareBackendException(msg)

    def allow_access(self, project_id, share_id, share_proto, access_type,
                     access_to, fpg, vfs):
        """Grant access to a share."""

        self._change_access(ALLOW, project_id, share_id, share_proto,
                            access_type, access_to, fpg, vfs)

    def deny_access(self, project_id, share_id, share_proto, access_type,
                    access_to, fpg, vfs):
        """Deny access to a share."""

        self._change_access(DENY, project_id, share_id, share_proto,
                            access_type, access_to, fpg, vfs)
