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

from oslo_utils import importutils
from oslo_utils import units
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.openstack.common import log as logging

hp3parclient = importutils.try_import("hp3parclient")
if hp3parclient:
    from hp3parclient import file_client


LOG = logging.getLogger(__name__)
DENY = '-'
ALLOW = '+'
OPEN_STACK_MANILA_FSHARE = 'OpenStack Manila fshare'


class HP3ParMediator(object):

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

        self.ssh_conn_timeout = kwargs.get('ssh_conn_timeout')
        self._client = None

    def do_setup(self):

        if hp3parclient is None:
            msg = _('You must install hp3parclient before using the 3PAR '
                    'driver.')
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

        if self.hp3par_debug:
            self._client.ssh.set_debug_flag(True)

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
    def ensure_prefix(id):
        if id.startswith('osf-'):
            return id
        else:
            return 'osf-%s' % id

    def create_share(self, share_id, share_proto, fpg, vfs,
                     fstore=None, sharedir=None, readonly=False, size=None):
        """Create the share and return its path.

        This method can create a share when called by the driver or when
        called locally from create_share_from_snapshot().  The optional
        parameters allow re-use.

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
            fstore = share_name
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
                try:
                    size_str = six.text_type(size)
                    result = self._client.setfsquota(
                        vfs, fpg=fpg, fstore=fstore,
                        scapacity=size_str, hcapacity=size_str)
                    LOG.debug("setfsquota result=%s", result)
                except Exception as e:
                    msg = (_('Failed to setfsquota on %(fstore)s: %(e)s') %
                           {'fstore': fstore, 'e': six.text_type(e)})
                    LOG.exception(msg)
                    raise exception.ShareBackendException(msg)

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

    def create_share_from_snapshot(self, share_id, share_proto, orig_share_id,
                                   snapshot_id, fpg, vfs):

        share_name = self.ensure_prefix(share_id)
        orig_share_name = self.ensure_prefix(orig_share_id)
        fstore = orig_share_name
        snapshot_tag = self.ensure_prefix(snapshot_id)
        snapshots = self.get_snapshots(fstore, snapshot_tag, fpg, vfs)

        if len(snapshots) != 1:
            msg = (_('Failed to create share from snapshot for '
                     'FPG/VFS/fstore/tag %(fpg)s/%(vfs)s/%(fstore)s/%(tag)s.'
                     ' Expected to find 1 snapshot, found %(count)s.') %
                   {'fpg': fpg, 'vfs': vfs, 'fstore': fstore,
                    'tag': snapshot_tag, 'count': len(snapshots)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        snapshot = snapshots[0]
        sharedir = '.snapshot/%s' % snapshot['snapName']

        return self.create_share(
            share_name,
            share_proto,
            fpg,
            vfs,
            fstore=fstore,
            sharedir=sharedir,
            readonly=True,
        )

    def delete_share(self, share_id, share_proto, fpg, vfs):

        share_name = self.ensure_prefix(share_id)
        fstore = self.get_fstore(share_id, share_proto, fpg, vfs)
        protocol = self.ensure_supported_protocol(share_proto)

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

    def create_snapshot(self, orig_share_id, snapshot_id, fpg, vfs):
        """Creates a snapshot of a share."""

        fstore = self.ensure_prefix(orig_share_id)
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

    def get_snapshots(self, orig_share_id, snapshot_tag, fpg, vfs):
        fstore = self.ensure_prefix(orig_share_id)
        try:
            pattern = '*_%s' % snapshot_tag
            result = self._client.getfsnap(
                pattern, fpg=fpg, vfs=vfs, fstore=fstore, pat=True)

            LOG.debug("getfsnap result=%s", result)

        except Exception as e:
            msg = (_('Failed to get snapshot for FPG/VFS/fstore/tag '
                     '%(fpg)s/%(vfs)s/%(fstore)s/%(tag)s: %(e)s') %
                   {'fpg': fpg, 'vfs': vfs, 'fstore': fstore,
                    'tag': snapshot_tag, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg)

        if result['total'] == 0:
            LOG.info((_LI('Found zero snapshots for FPG/VFS/fstore/tag '
                          '%(fpg)s/%(vfs)s/%(fstore)s/%(tag)s.') %
                      {'fpg': fpg, 'vfs': vfs, 'fstore': fstore,
                       'tag': snapshot_tag}))

        return result['members']

    def delete_snapshot(self, orig_share_id, snapshot_id, fpg, vfs):
        """Deletes a snapshot of a share."""

        fstore = self.ensure_prefix(orig_share_id)
        snapshot_tag = self.ensure_prefix(snapshot_id)
        snapshots = self.get_snapshots(fstore, snapshot_tag, fpg, vfs)

        if not snapshots:
            return

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

        # Tag should be unique enough to only return one, but this method
        # doesn't really need to know that.  So just loop.
        for snapshot in snapshots:
            try:
                snapname = snapshot['snapName']
                result = self._client.removefsnap(
                    vfs, fstore, snapname=snapname, fpg=fpg)

                LOG.debug("removefsnap result=%s", result)

            except Exception as e:
                msg = (_('Failed to delete snapshot for FPG/VFS/fstore '
                         '%(fpg)s/%(vfs)s/%(fstore)s: %(e)s') %
                       {'fpg': fpg, 'vfs': vfs, 'fstore': fstore,
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

    def _change_access(self, plus_or_minus, fstore, share_id, share_proto,
                       access_type, access_to, fpg, vfs):
        """Allow or deny access to a share.

        Plus_or_minus character indicates add to allow list (+) or remove from
        allow list (-).
        """

        share_name = self.ensure_prefix(share_id)
        fstore = self.ensure_prefix(fstore)

        protocol = self.ensure_supported_protocol(share_proto)
        self.validate_access_type(protocol, access_type)

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

    def get_fstore(self, share_id, share_proto, fpg, vfs):

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id)
        try:
            shares = self._client.getfshare(protocol,
                                            share_name,
                                            fpg=fpg,
                                            vfs=vfs)
        except Exception as e:
            msg = (_('Unexpected exception while getting share list: %s') %
                   six.text_type(e))
            raise exception.ShareBackendException(msg)

        members = shares['members']
        if members:
            return members[0].get('fstoreName')

    def allow_access(self, share_id, share_proto, access_type, access_to,
                     fpg, vfs):
        """Grant access to a share."""

        fstore = self.get_fstore(share_id, share_proto, fpg, vfs)
        self._change_access(ALLOW, fstore, share_id, share_proto,
                            access_type, access_to, fpg, vfs)

    def deny_access(self, share_id, share_proto, access_type, access_to,
                    fpg, vfs):
        """Deny access to a share."""

        fstore = self.get_fstore(share_id, share_proto, fpg, vfs)
        if fstore:
            self._change_access(DENY, fstore, share_id, share_proto,
                                access_type, access_to, fpg, vfs)
