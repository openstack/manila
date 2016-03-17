# Copyright 2015 Hewlett Packard Enterprise Development LP
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

"""HPE 3PAR Mediator for OpenStack Manila.

This 'mediator' de-couples the 3PAR focused client from the OpenStack focused
driver.
"""

from oslo_log import log
from oslo_utils import importutils
from oslo_utils import units
import six

from manila import exception
from manila import utils
from manila.i18n import _, _LI, _LW

hpe3parclient = importutils.try_import("hpe3parclient")
if hpe3parclient:
    from hpe3parclient import file_client


LOG = log.getLogger(__name__)
MIN_CLIENT_VERSION = (4, 0, 0)
DENY = '-'
ALLOW = '+'
OPEN_STACK_MANILA = 'OpenStack Manila'
FULL = 1
THIN = 2
DEDUPE = 6
ENABLED = 1
DISABLED = 2
CACHE = 'cache'
CONTINUOUS_AVAIL = 'continuous_avail'
ACCESS_BASED_ENUM = 'access_based_enum'
SMB_EXTRA_SPECS_MAP = {
    CACHE: CACHE,
    CONTINUOUS_AVAIL: 'ca',
    ACCESS_BASED_ENUM: 'abe',
}
IP_ALREADY_EXISTS = 'IP address %s already exists'
USER_ALREADY_EXISTS = '"allow" permission already exists for "%s"'
DOES_NOT_EXIST = 'does not exist, cannot'
LOCAL_IP = '127.0.0.1'
LOCAL_IP_RO = '127.0.0.2'
SUPER_SHARE = 'OPENSTACK_SUPER_SHARE'


class HPE3ParMediator(object):
    """3PAR client-facing code for the 3PAR driver.

    Version history:
        1.0.0 - Begin Liberty development (post-Kilo)
        1.0.1 - Report thin/dedup/hp_flash_cache capabilities
        1.0.2 - Add share server/share network support
        1.0.3 - Use hp3par prefix for share types and capabilities
        2.0.0 - Rebranded HP to HPE
        2.0.1 - Add access_level (e.g. read-only support)
        2.0.2 - Add extend/shrink
        2.0.3 - Fix SMB read-only access (added in 2.0.1)
        2.0.4 - Remove file tree on delete when using nested shares #1538800

    """

    VERSION = "2.0.4"

    def __init__(self, **kwargs):

        self.hpe3par_username = kwargs.get('hpe3par_username')
        self.hpe3par_password = kwargs.get('hpe3par_password')
        self.hpe3par_api_url = kwargs.get('hpe3par_api_url')
        self.hpe3par_debug = kwargs.get('hpe3par_debug')
        self.hpe3par_san_ip = kwargs.get('hpe3par_san_ip')
        self.hpe3par_san_login = kwargs.get('hpe3par_san_login')
        self.hpe3par_san_password = kwargs.get('hpe3par_san_password')
        self.hpe3par_san_ssh_port = kwargs.get('hpe3par_san_ssh_port')
        self.hpe3par_san_private_key = kwargs.get('hpe3par_san_private_key')
        self.hpe3par_fstore_per_share = kwargs.get('hpe3par_fstore_per_share')
        self.hpe3par_require_cifs_ip = kwargs.get('hpe3par_require_cifs_ip')
        self.hpe3par_share_ip_address = kwargs.get('hpe3par_share_ip_address')
        self.hpe3par_cifs_admin_access_username = (
            kwargs.get('hpe3par_cifs_admin_access_username'))
        self.hpe3par_cifs_admin_access_password = (
            kwargs.get('hpe3par_cifs_admin_access_password'))
        self.hpe3par_cifs_admin_access_domain = (
            kwargs.get('hpe3par_cifs_admin_access_domain'))
        self.hpe3par_share_mount_path = kwargs.get('hpe3par_share_mount_path')
        self.my_ip = kwargs.get('my_ip')

        self.ssh_conn_timeout = kwargs.get('ssh_conn_timeout')
        self._client = None
        self.client_version = None

    @staticmethod
    def no_client():
        return hpe3parclient is None

    def do_setup(self):

        if self.no_client():
            msg = _('You must install hpe3parclient before using the 3PAR '
                    'driver. Run "pip install --upgrade python-3parclient" '
                    'to upgrade the hpe3parclient.')
            LOG.error(msg)
            raise exception.HPE3ParInvalidClient(message=msg)

        self.client_version = hpe3parclient.version_tuple
        if self.client_version < MIN_CLIENT_VERSION:
            msg = (_('Invalid hpe3parclient version found (%(found)s). '
                     'Version %(minimum)s or greater required. Run "pip'
                     ' install --upgrade python-3parclient" to upgrade'
                     ' the hpe3parclient.') %
                   {'found': '.'.join(map(six.text_type, self.client_version)),
                    'minimum': '.'.join(map(six.text_type,
                                            MIN_CLIENT_VERSION))})
            LOG.error(msg)
            raise exception.HPE3ParInvalidClient(message=msg)

        try:
            self._client = file_client.HPE3ParFilePersonaClient(
                self.hpe3par_api_url)
        except Exception as e:
            msg = (_('Failed to connect to HPE 3PAR File Persona Client: %s') %
                   six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        try:
            ssh_kwargs = {}
            if self.hpe3par_san_ssh_port:
                ssh_kwargs['port'] = self.hpe3par_san_ssh_port
            if self.ssh_conn_timeout:
                ssh_kwargs['conn_timeout'] = self.ssh_conn_timeout
            if self.hpe3par_san_private_key:
                ssh_kwargs['privatekey'] = self.hpe3par_san_private_key

            self._client.setSSHOptions(
                self.hpe3par_san_ip,
                self.hpe3par_san_login,
                self.hpe3par_san_password,
                **ssh_kwargs
            )

        except Exception as e:
            msg = (_('Failed to set SSH options for HPE 3PAR File Persona '
                     'Client: %s') % six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        LOG.info(_LI("HPE3ParMediator %(version)s, "
                     "hpe3parclient %(client_version)s"),
                 {"version": self.VERSION,
                  "client_version": hpe3parclient.get_version_string()})

        try:
            wsapi_version = self._client.getWsApiVersion()['build']
            LOG.info(_LI("3PAR WSAPI %s"), wsapi_version)
        except Exception as e:
            msg = (_('Failed to get 3PAR WSAPI version: %s') %
                   six.text_type(e))
            LOG.exception(msg)
            raise exception.ShareBackendException(message=msg)

        if self.hpe3par_debug:
            self._client.debug_rest(True)  # Includes SSH debug (setSSH above)

    def _wsapi_login(self):
        try:
            self._client.login(self.hpe3par_username, self.hpe3par_password)
        except Exception as e:
            msg = (_("Failed to Login to 3PAR (%(url)s) as %(user)s "
                     "because: %(err)s") %
                   {'url': self.hpe3par_api_url,
                    'user': self.hpe3par_username,
                    'err': six.text_type(e)})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def _wsapi_logout(self):
        try:
            self._client.http.unauthenticate()
        except Exception as e:
            msg = _LW("Failed to Logout from 3PAR (%(url)s) because %(err)s")
            LOG.warning(msg, {'url': self.hpe3par_api_url,
                              'err': six.text_type(e)})
            # don't raise exception on logout()

    def get_provisioned_gb(self, fpg):
        total_mb = 0
        try:
            result = self._client.getfsquota(fpg=fpg)
        except Exception as e:
            result = {'message': six.text_type(e)}

        error_msg = result.get('message')
        if error_msg:
            message = (_('Error while getting fsquotas for FPG '
                         '%(fpg)s: %(msg)s') %
                       {'fpg': fpg, 'msg': error_msg})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        for fsquota in result['members']:
            total_mb += float(fsquota['hardBlock'])
        return total_mb / units.Ki

    def get_fpg_status(self, fpg):
        """Get capacity and capabilities for FPG."""

        try:
            result = self._client.getfpg(fpg)
        except Exception as e:
            msg = (_('Failed to get capacity for fpg %(fpg)s: %(e)s') %
                   {'fpg': fpg, 'e': six.text_type(e)})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        if result['total'] != 1:
            msg = (_('Failed to get capacity for fpg %s.') % fpg)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        member = result['members'][0]
        total_capacity_gb = float(member['capacityKiB']) / units.Mi
        free_capacity_gb = float(member['availCapacityKiB']) / units.Mi

        volumes = member['vvs']
        if isinstance(volumes, list):
            volume = volumes[0]  # Use first name from list
        else:
            volume = volumes  # There is just a name

        self._wsapi_login()
        try:
            volume_info = self._client.getVolume(volume)
            volume_set = self._client.getVolumeSet(fpg)
        finally:
            self._wsapi_logout()

        provisioning_type = volume_info['provisioningType']
        if provisioning_type not in (THIN, FULL, DEDUPE):
            msg = (_('Unexpected provisioning type for FPG %(fpg)s: '
                     '%(ptype)s.') % {'fpg': fpg, 'ptype': provisioning_type})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        dedupe = provisioning_type == DEDUPE
        thin_provisioning = provisioning_type in (THIN, DEDUPE)

        flash_cache_policy = volume_set.get('flashCachePolicy', DISABLED)
        hpe3par_flash_cache = flash_cache_policy == ENABLED

        status = {
            'total_capacity_gb': total_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
            'thin_provisioning': thin_provisioning,
            'dedupe': dedupe,
            'hpe3par_flash_cache': hpe3par_flash_cache,
            'hp3par_flash_cache': hpe3par_flash_cache,
        }

        if thin_provisioning:
            status['provisioned_capacity_gb'] = self.get_provisioned_gb(fpg)

        return status

    @staticmethod
    def ensure_supported_protocol(share_proto):
        protocol = share_proto.lower()
        if protocol == 'cifs':
            protocol = 'smb'
        if protocol not in ['smb', 'nfs']:
            message = (_('Invalid protocol. Expected nfs or smb. Got %s.') %
                       protocol)
            LOG.error(message)
            raise exception.InvalidInput(message)
        return protocol

    @staticmethod
    def other_protocol(share_proto):
        """Given 'nfs' or 'smb' (or equivalent) return the other one."""
        protocol = HPE3ParMediator.ensure_supported_protocol(share_proto)
        return 'nfs' if protocol == 'smb' else 'smb'

    @staticmethod
    def ensure_prefix(uid, protocol=None, readonly=False):
        if uid.startswith('osf-'):
            return uid

        if protocol:
            proto = '-%s' % HPE3ParMediator.ensure_supported_protocol(protocol)
        else:
            proto = ''

        if readonly:
            ro = '-ro'
        else:
            ro = ''

        # Format is osf[-ro]-{nfs|smb}-uid
        return 'osf%s%s-%s' % (proto, ro, uid)

    @staticmethod
    def _get_nfs_options(extra_specs, readonly):
        """Validate the NFS extra_specs and return the options to use."""

        nfs_options = extra_specs.get('hpe3par:nfs_options')
        if nfs_options is None:
            nfs_options = extra_specs.get('hp3par:nfs_options')
            if nfs_options:
                msg = _LW("hp3par:nfs_options is deprecated. Use "
                          "hpe3par:nfs_options instead.")
                LOG.warning(msg)

        if nfs_options:
            options = nfs_options.split(',')
        else:
            options = []

        # rw, ro, and (no)root_squash (in)secure options are not allowed in
        # extra_specs because they will be forcibly set below.
        # no_subtree_check and fsid are not allowed per 3PAR support.
        # Other strings will be allowed to be sent to the 3PAR which will do
        # further validation.
        options_not_allowed = ['ro', 'rw',
                               'no_root_squash', 'root_squash',
                               'secure', 'insecure',
                               'no_subtree_check', 'fsid']

        invalid_options = [
            option for option in options if option in options_not_allowed
        ]

        if invalid_options:
            raise exception.InvalidInput(_('Invalid hp3par:nfs_options or '
                                           'hpe3par:nfs_options in '
                                           'extra-specs. The following '
                                           'options are not allowed: %s') %
                                         invalid_options)

        options.append('ro' if readonly else 'rw')
        options.append('no_root_squash')
        options.append('insecure')

        return ','.join(options)

    def _build_createfshare_kwargs(self, protocol, fpg, fstore, readonly,
                                   sharedir, extra_specs, comment):
        createfshare_kwargs = dict(fpg=fpg,
                                   fstore=fstore,
                                   sharedir=sharedir,
                                   comment=comment)

        if 'hp3par_flash_cache' in extra_specs:
            msg = _LW("hp3par_flash_cache is deprecated. Use "
                      "hpe3par_flash_cache instead.")
            LOG.warning(msg)

        if protocol == 'nfs':
            # New NFS shares needs seed IP to prevent "all" access.
            # Readonly and readwrite NFS shares client IPs cannot overlap.
            if readonly:
                createfshare_kwargs['clientip'] = LOCAL_IP_RO
            else:
                createfshare_kwargs['clientip'] = LOCAL_IP
            options = self._get_nfs_options(extra_specs, readonly)
            createfshare_kwargs['options'] = options
        else:

            # To keep the original (Kilo, Liberty) behavior where CIFS IP
            # access rules were required in addition to user rules enable
            # this to use a local seed IP instead of the default (all allowed).
            if self.hpe3par_require_cifs_ip:
                createfshare_kwargs['allowip'] = LOCAL_IP

            smb_opts = (ACCESS_BASED_ENUM, CONTINUOUS_AVAIL, CACHE)

            for smb_opt in smb_opts:
                opt_value = extra_specs.get('hpe3par:smb_%s' % smb_opt)
                if opt_value is None:
                    opt_value = extra_specs.get('hp3par:smb_%s' % smb_opt)
                    if opt_value:
                        msg = _LW("hp3par:smb_* is deprecated. Use "
                                  "hpe3par:smb_* instead.")
                        LOG.warning(msg)

                if opt_value:
                    opt_key = SMB_EXTRA_SPECS_MAP[smb_opt]
                    createfshare_kwargs[opt_key] = opt_value
        return createfshare_kwargs

    def _update_capacity_quotas(self, fstore, new_size, old_size, fpg, vfs):

        @utils.synchronized('hpe3par-update-quota-' + fstore)
        def _sync_update_capacity_quotas(fstore, new_size, old_size, fpg, vfs):
            """Update 3PAR quotas and return setfsquota output."""

            if self.hpe3par_fstore_per_share:
                hcapacity = six.text_type(new_size * units.Ki)
                scapacity = hcapacity
            else:
                hard_size_mb = (new_size - old_size) * units.Ki
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

            return self._client.setfsquota(vfs,
                                           fpg=fpg,
                                           fstore=fstore,
                                           scapacity=scapacity,
                                           hcapacity=hcapacity)

        try:
            result = _sync_update_capacity_quotas(
                fstore, new_size, old_size, fpg, vfs)
            LOG.debug("setfsquota result=%s", result)
        except Exception as e:
            msg = (_('Failed to update capacity quota '
                     '%(size)s on %(fstore)s with exception: %(e)s') %
                   {'size': new_size - old_size,
                    'fstore': fstore,
                    'e': six.text_type(e)})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        # Non-empty result is an error message returned from the 3PAR
        if result:
            msg = (_('Failed to update capacity quota '
                     '%(size)s on %(fstore)s with error: %(error)s') %
                   {'size': new_size - old_size,
                    'fstore': fstore,
                    'error': result})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def _create_share(self, project_id, share_id, protocol, extra_specs,
                      fpg, vfs, fstore, sharedir, readonly, size, comment):
        share_name = self.ensure_prefix(share_id, readonly=readonly)

        if not (sharedir or self.hpe3par_fstore_per_share):
            sharedir = share_name

        if fstore:
            use_existing_fstore = True
        else:
            use_existing_fstore = False
            if self.hpe3par_fstore_per_share:
                # Do not use -ro in the fstore name.
                fstore = self.ensure_prefix(share_id, readonly=False)
            else:
                fstore = self.ensure_prefix(project_id, protocol)

        createfshare_kwargs = self._build_createfshare_kwargs(protocol,
                                                              fpg,
                                                              fstore,
                                                              readonly,
                                                              sharedir,
                                                              extra_specs,
                                                              comment)

        if not use_existing_fstore:

            try:
                result = self._client.createfstore(
                    vfs, fstore, fpg=fpg,
                    comment=comment)
                LOG.debug("createfstore result=%s", result)
            except Exception as e:
                msg = (_('Failed to create fstore %(fstore)s: %(e)s') %
                       {'fstore': fstore, 'e': six.text_type(e)})
                LOG.exception(msg)
                raise exception.ShareBackendException(msg)

            if size:
                self._update_capacity_quotas(fstore, size, 0, fpg, vfs)

        try:

            if readonly and protocol == 'nfs':
                # For NFS, RO is a 2nd 3PAR share pointing to same sharedir
                share_name = self.ensure_prefix(share_id, readonly=readonly)

            result = self._client.createfshare(protocol,
                                               vfs,
                                               share_name,
                                               **createfshare_kwargs)

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
            LOG.error(msg)
            raise exception.ShareBackendException(msg)
        return result['members'][0]

    def create_share(self, project_id, share_id, share_proto, extra_specs,
                     fpg, vfs,
                     fstore=None, sharedir=None, readonly=False, size=None,
                     comment=OPEN_STACK_MANILA):
        """Create the share and return its path.

        This method can create a share when called by the driver or when
        called locally from create_share_from_snapshot().  The optional
        parameters allow re-use.

        :param project_id: The tenant ID.
        :param share_id: The share-id with or without osf- prefix.
        :param share_proto: The protocol (to map to smb or nfs)
        :param extra_specs: The share type extra-specs
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
        share = self._create_share(project_id,
                                   share_id,
                                   protocol,
                                   extra_specs,
                                   fpg,
                                   vfs,
                                   fstore,
                                   sharedir,
                                   readonly,
                                   size,
                                   comment)

        if protocol == 'nfs':
            return share['sharePath']
        else:
            return share['shareName']

    def create_share_from_snapshot(self, share_id, share_proto, extra_specs,
                                   orig_project_id, orig_share_id,
                                   snapshot_id, fpg, vfs,
                                   comment=OPEN_STACK_MANILA):

        protocol = self.ensure_supported_protocol(share_proto)
        snapshot_tag = self.ensure_prefix(snapshot_id)
        orig_share_name = self.ensure_prefix(orig_share_id)

        snapshot = self._find_fsnap(orig_project_id,
                                    orig_share_name,
                                    protocol,
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
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        fstore = snapshot['fstoreName']
        if fstore == orig_share_name:
            # No subdir for original share created with fstore_per_share
            sharedir = '.snapshot/%s' % snapshot['snapName']
        else:
            sharedir = '.snapshot/%s/%s' % (snapshot['snapName'],
                                            orig_share_name)

        return self.create_share(
            orig_project_id,
            share_id,
            protocol,
            extra_specs,
            fpg,
            vfs,
            fstore=fstore,
            sharedir=sharedir,
            readonly=True,
            comment=comment,
        )

    def _delete_share(self, share_name, protocol, fpg, vfs, fstore):
        try:
            self._client.removefshare(
                protocol, vfs, share_name, fpg=fpg, fstore=fstore)

        except Exception as e:
            msg = (_('Failed to remove share %(share_name)s: %(e)s') %
                   {'share_name': share_name, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

    def delete_share(self, project_id, share_id, share_proto, fpg, vfs):

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id)
        fstore = self._find_fstore(project_id,
                                   share_name,
                                   protocol,
                                   fpg,
                                   vfs,
                                   allow_cross_protocol=True)

        if fstore:
            self._delete_share(share_name, protocol, fpg, vfs, fstore)

        share_name_ro = self.ensure_prefix(share_id, readonly=True)
        if not fstore:
            fstore = self._find_fstore(project_id,
                                       share_name_ro,
                                       protocol,
                                       fpg,
                                       vfs,
                                       allow_cross_protocol=True)
        if fstore:
            self._delete_share(share_name_ro, protocol, fpg, vfs, fstore)

        if not self.hpe3par_fstore_per_share:
            # Attempt to remove file tree on delete when using nested shares.
            # If the file tree cannot be removed for whatever reason, we will
            # not treat this as an error_deleting issue. We will allow the
            # delete to continue as requested.
            self._delete_file_tree(share_name, protocol, fpg, vfs, fstore)

        if fstore == share_name:
            try:
                self._client.removefstore(vfs, fstore, fpg=fpg)
            except Exception as e:
                msg = (_('Failed to remove fstore %(fstore)s: %(e)s') %
                       {'fstore': fstore, 'e': six.text_type(e)})
                LOG.exception(msg)
                raise exception.ShareBackendException(msg=msg)

    def _delete_file_tree(self, share_name, protocol, fpg, vfs, fstore):
        # If the share protocol is CIFS, we need to make sure the admin
        # provided the proper config values. If they have not, we can simply
        # return out and log a warning.
        if protocol == "smb" and (not self.hpe3par_cifs_admin_access_username
           or not self.hpe3par_cifs_admin_access_password):
            LOG.warning(_LW("hpe3par_cifs_admin_access_username and "
                            "hpe3par_cifs_admin_access_password must be "
                            "provided in order for the file tree to be "
                            "properly deleted."))
            return

        mount_location = "%s%s" % (self.hpe3par_share_mount_path, share_name)
        share_dir = mount_location + "/%s" % share_name

        # Create the super share.
        self._create_super_share(protocol, fpg, vfs, fstore)

        # Create the mount directory.
        self._create_mount_directory(mount_location)

        # Mount the super share.
        self._mount_super_share(protocol, mount_location, fpg, vfs, fstore)

        # Delete the share from the super share.
        self._delete_share_directory(share_dir)

        # Unmount the super share.
        self._unmount_super_share(mount_location)

        # Delete the mount directory.
        self._delete_share_directory(mount_location)

    def _create_super_share(self, protocol, fpg, vfs, fstore, readonly=False):
        sharedir = ''
        extra_specs = {}
        comment = 'OpenStack super share used to delete nested shares.'
        createfshare_kwargs = self._build_createfshare_kwargs(protocol,
                                                              fpg,
                                                              fstore,
                                                              readonly,
                                                              sharedir,
                                                              extra_specs,
                                                              comment)

        # If the share is NFS, we need to give the host access to the share in
        # order to properly mount it.
        if protocol == 'nfs':
            createfshare_kwargs['clientip'] = self.my_ip
        else:
            createfshare_kwargs['allowip'] = self.my_ip

        try:
            result = self._client.createfshare(protocol,
                                               vfs,
                                               SUPER_SHARE,
                                               **createfshare_kwargs)
            LOG.debug("createfshare for %(name)s, result=%(result)s",
                      {'name': SUPER_SHARE, 'result': result})
        except Exception as e:
            msg = (_('Failed to create share %(share_name)s: %(e)s'),
                   {'share_name': SUPER_SHARE, 'e': six.text_type(e)})
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

        # If the share is CIFS, we need to grant access to the specified admin.
        if protocol == 'smb':
            user = '+%s:fullcontrol' % self.hpe3par_cifs_admin_access_username
            setfshare_kwargs = {
                'fpg': fpg,
                'fstore': fstore,
                'comment': comment,
                'allowperm': user,
            }
            try:
                result = self._client.setfshare(
                    protocol, vfs, SUPER_SHARE, **setfshare_kwargs)
            except Exception as err:
                message = (_("There was an error adding permissions: "
                             "%s.") % six.text_type(err))
                raise exception.ShareMountException(reason=message)

    def _create_mount_directory(self, mount_location):
        try:
            utils.execute('mkdir', mount_location, run_as_root=True)
        except Exception as err:
            message = (_LW("There was an error creating mount directory: "
                           "%s. The nested file tree will not be deleted."),
                       six.text_type(err))
            LOG.warning(message)

    def _mount_super_share(self, protocol, mount_location, fpg, vfs, fstore):
        try:
            mount_path = self._generate_mount_path(protocol, fpg, vfs, fstore)
            if protocol == 'nfs':
                utils.execute('mount', '-t', 'nfs', mount_path, mount_location,
                              run_as_root=True)
                LOG.debug("Execute mount. mount_location: %s", mount_location)
            else:
                user = ('username=' + self.hpe3par_cifs_admin_access_username +
                        ',password=' +
                        self.hpe3par_cifs_admin_access_password +
                        ',domain=' + self.hpe3par_cifs_admin_access_domain)
                utils.execute('mount', '-t', 'cifs', mount_path,
                              mount_location, '-o', user, run_as_root=True)
        except Exception as err:
            message = (_LW("There was an error mounting the super share: "
                           "%s. The nested file tree will not be deleted."),
                       six.text_type(err))
            LOG.warning(message)

    def _unmount_super_share(self, mount_location):
        try:
            utils.execute('umount', mount_location, run_as_root=True)
        except Exception as err:
            message = (_LW("There was an error unmounting the super share: "
                           "%s. The nested file tree will not be deleted."),
                       six.text_type(err))
            LOG.warning(message)

    def _delete_share_directory(self, directory):
        try:
            utils.execute('rm', '-rf', directory, run_as_root=True)
        except Exception as err:
            message = (_LW("There was an error removing the share: "
                           "%s. The nested file tree will not be deleted."),
                       six.text_type(err))
            LOG.warning(message)

    def _generate_mount_path(self, protocol, fpg, vfs, fstore):
        path = None
        if protocol == 'nfs':
            path = (("%(share_ip)s:/%(fpg)s/%(vfs)s/%(fstore)s/") %
                    {'share_ip': self.hpe3par_share_ip_address,
                     'fpg': fpg,
                     'vfs': vfs,
                     'fstore': fstore})
        else:
            path = (("//%(share_ip)s/%(share_name)s/") %
                    {'share_ip': self.hpe3par_share_ip_address,
                     'share_name': SUPER_SHARE})
        return path

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

    @staticmethod
    def _is_share_from_snapshot(fshare):

        path = fshare.get('shareDir')
        if path:
            return '.snapshot' in path.split('/')

        path = fshare.get('sharePath')
        return path and '.snapshot' in path.split('/')

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
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        if self._is_share_from_snapshot(fshare):
            msg = (_('Failed to create snapshot for FPG/VFS/fshare '
                     '%(fpg)s/%(vfs)s/%(fshare)s: Share is a read-only '
                     'share of an existing snapshot.') %
                   {'fpg': fpg, 'vfs': vfs, 'fshare': orig_share_id})
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

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
            raise exception.ShareBackendException(msg=msg)

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
    def _validate_access_type(protocol, access_type):

        if access_type not in ('ip', 'user'):
            msg = (_("Invalid access type.  Expected 'ip' or 'user'.  "
                     "Actual '%s'.") % access_type)
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if protocol == 'nfs' and access_type != 'ip':
            msg = (_("Invalid NFS access type.  HPE 3PAR NFS supports 'ip'. "
                     "Actual '%s'.") % access_type)
            LOG.error(msg)
            raise exception.HPE3ParInvalid(msg)

        return protocol

    @staticmethod
    def _validate_access_level(protocol, access_type, access_level, fshare):

        readonly = access_level == 'ro'
        snapshot = HPE3ParMediator._is_share_from_snapshot(fshare)

        if snapshot and not readonly:
            reason = _('3PAR shares from snapshots require read-only access')
            LOG.error(reason)
            raise exception.InvalidShareAccess(reason=reason)

        if protocol == 'smb' and access_type == 'ip' and snapshot != readonly:
            msg = (_("Invalid CIFS access rule. HPE 3PAR optionally supports "
                     "IP access rules for CIFS shares, but they must be "
                     "read-only for shares from snapshots and read-write for "
                     "other shares. Use the required CIFS 'user' access rules "
                     "to refine access."))
            LOG.error(msg)
            raise exception.InvalidShareAccess(reason=msg)

    @staticmethod
    def ignore_benign_access_results(plus_or_minus, access_type, access_to,
                                     result):

        # TODO(markstur): Remove the next line when hpe3parclient is fixed.
        result = [x for x in result if x != '\r']

        if result:
            if plus_or_minus == DENY:
                if DOES_NOT_EXIST in result[0]:
                    return None
            else:
                if access_type == 'user':
                    if USER_ALREADY_EXISTS % access_to in result[0]:
                        return None
                elif IP_ALREADY_EXISTS % access_to in result[0]:
                    return None
        return result

    def _change_access(self, plus_or_minus, project_id, share_id, share_proto,
                       access_type, access_to, access_level,
                       fpg, vfs, extra_specs=None):
        """Allow or deny access to a share.

        Plus_or_minus character indicates add to allow list (+) or remove from
        allow list (-).
        """

        readonly = access_level == 'ro'
        protocol = self.ensure_supported_protocol(share_proto)

        try:
            self._validate_access_type(protocol, access_type)
        except Exception:
            if plus_or_minus == DENY:
                # Catch invalid rules for deny. Allow them to be deleted.
                return
            else:
                raise

        fshare = self._find_fshare(project_id,
                                   share_id,
                                   protocol,
                                   fpg,
                                   vfs,
                                   readonly=readonly)
        if not fshare:
            # Change access might apply to the share with the name that
            # does not match the access_level prefix.
            other_fshare = self._find_fshare(project_id,
                                             share_id,
                                             protocol,
                                             fpg,
                                             vfs,
                                             readonly=not readonly)
            if other_fshare:

                if plus_or_minus == DENY:
                    # Try to deny rule from 'other' share for SMB or legacy.
                    fshare = other_fshare

                elif self._is_share_from_snapshot(other_fshare):
                    # Found a share-from-snapshot from before
                    # "-ro" was added to the name. Use it.
                    fshare = other_fshare

                elif protocol == 'nfs':
                    # We don't have the RO|RW share we need, but the
                    # opposite one already exists. It is OK to create
                    # the one we need for ALLOW with NFS (not from snapshot).
                    fstore = other_fshare.get('fstoreName')
                    sharedir = other_fshare.get('shareDir')
                    comment = other_fshare.get('comment')

                    fshare = self._create_share(project_id,
                                                share_id,
                                                protocol,
                                                extra_specs,
                                                fpg,
                                                vfs,
                                                fstore=fstore,
                                                sharedir=sharedir,
                                                readonly=readonly,
                                                size=None,
                                                comment=comment)
                else:
                    # SMB only has one share for RO and RW. Try to use it.
                    fshare = other_fshare

            if not fshare:
                msg = _('Failed to change (%(change)s) access '
                        'to FPG/share %(fpg)s/%(share)s '
                        'for %(type)s %(to)s %(level)s): '
                        'Share does not exist on 3PAR.')
                msg_data = {
                    'change': plus_or_minus,
                    'fpg': fpg,
                    'share': share_id,
                    'type': access_type,
                    'to': access_to,
                    'level': access_level,
                }

                if plus_or_minus == DENY:
                    LOG.warning(msg, msg_data)
                    return
                else:
                    raise exception.HPE3ParInvalid(err=msg % msg_data)

        try:
            self._validate_access_level(
                protocol, access_type, access_level, fshare)
        except exception.InvalidShareAccess as e:
            if plus_or_minus == DENY:
                # Allow invalid access rules to be deleted.
                msg = _('Ignoring deny invalid access rule '
                        'for FPG/share %(fpg)s/%(share)s '
                        'for %(type)s %(to)s %(level)s): %(e)s')
                msg_data = {
                    'change': plus_or_minus,
                    'fpg': fpg,
                    'share': share_id,
                    'type': access_type,
                    'to': access_to,
                    'level': access_level,
                    'e': six.text_type(e),
                }
                LOG.info(msg, msg_data)
                return
            else:
                raise

        share_name = fshare.get('shareName')
        setfshare_kwargs = {
            'fpg': fpg,
            'fstore': fshare.get('fstoreName'),
            'comment': fshare.get('comment'),
        }

        if protocol == 'nfs':
            access_change = '%s%s' % (plus_or_minus, access_to)
            setfshare_kwargs['clientip'] = access_change

        elif protocol == 'smb':

            if access_type == 'ip':
                access_change = '%s%s' % (plus_or_minus, access_to)
                setfshare_kwargs['allowip'] = access_change

            else:
                access_str = 'read' if readonly else 'fullcontrol'
                perm = '%s%s:%s' % (plus_or_minus, access_to, access_str)
                setfshare_kwargs['allowperm'] = perm

        try:
            result = self._client.setfshare(
                protocol, vfs, share_name, **setfshare_kwargs)

            result = self.ignore_benign_access_results(
                plus_or_minus, access_type, access_to, result)

        except Exception as e:
            result = six.text_type(e)

        LOG.debug("setfshare result=%s", result)
        if result:
            msg = (_('Failed to change (%(change)s) access to FPG/share '
                     '%(fpg)s/%(share)s for %(type)s %(to)s %(level)s: '
                     '%(error)s') %
                   {'change': plus_or_minus,
                    'fpg': fpg,
                    'share': share_id,
                    'type': access_type,
                    'to': access_to,
                    'level': access_level,
                    'error': result})
            raise exception.ShareBackendException(msg=msg)

    def _find_fstore(self, project_id, share_id, share_proto, fpg, vfs,
                     allow_cross_protocol=False):

        share = self._find_fshare(project_id,
                                  share_id,
                                  share_proto,
                                  fpg,
                                  vfs,
                                  allow_cross_protocol=allow_cross_protocol)

        return share.get('fstoreName') if share else None

    def _find_fshare(self, project_id, share_id, share_proto, fpg, vfs,
                     allow_cross_protocol=False, readonly=False):

        share = self._find_fshare_with_proto(project_id,
                                             share_id,
                                             share_proto,
                                             fpg,
                                             vfs,
                                             readonly=readonly)

        if not share and allow_cross_protocol:
            other_proto = self.other_protocol(share_proto)
            share = self._find_fshare_with_proto(project_id,
                                                 share_id,
                                                 other_proto,
                                                 fpg,
                                                 vfs,
                                                 readonly=readonly)
        return share

    def _find_fshare_with_proto(self, project_id, share_id, share_proto,
                                fpg, vfs, readonly=False):

        protocol = self.ensure_supported_protocol(share_proto)
        share_name = self.ensure_prefix(share_id, readonly=readonly)

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
            raise exception.ShareBackendException(msg=msg)

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

    def allow_access(self, project_id, share_id, share_proto,
                     extra_specs, access_type, access_to, access_level,
                     fpg, vfs):
        """Grant access to a share."""

        self._change_access(ALLOW,
                            project_id,
                            share_id,
                            share_proto,
                            access_type,
                            access_to,
                            access_level,
                            fpg,
                            vfs,
                            extra_specs=extra_specs)

    def deny_access(self, project_id, share_id, share_proto,
                    access_type, access_to, access_level, fpg, vfs):
        """Deny access to a share."""

        self._change_access(DENY,
                            project_id,
                            share_id,
                            share_proto,
                            access_type,
                            access_to,
                            access_level,
                            fpg,
                            vfs)

    def resize_share(self, project_id, share_id, share_proto,
                     new_size, old_size, fpg, vfs):
        """Extends or shrinks size of existing share."""

        share_name = self.ensure_prefix(share_id)
        fstore = self._find_fstore(project_id,
                                   share_name,
                                   share_proto,
                                   fpg,
                                   vfs,
                                   allow_cross_protocol=False)

        if not fstore:
            msg = (_('Cannot resize share because it was not found.'))
            raise exception.InvalidShare(reason=msg)

        self._update_capacity_quotas(fstore, new_size, old_size, fpg, vfs)

    def fsip_exists(self, fsip):
        """Try to get FSIP. Return True if it exists."""

        vfs = fsip['vfs']
        fpg = fsip['fspool']

        try:
            result = self._client.getfsip(vfs, fpg=fpg)
            LOG.debug("getfsip result: %s", result)
        except Exception as e:
            LOG.exception(e)
            msg = (_('Failed to get FSIPs for FPG/VFS %(fspool)s/%(vfs)s.') %
                   fsip)
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

        for member in result['members']:
            if all(item in member.items() for item in fsip.items()):
                return True

        return False

    def create_fsip(self, ip, subnet, vlantag, fpg, vfs):

        vlantag_str = six.text_type(vlantag) if vlantag else '0'

        # Try to create it. It's OK if it already exists.
        try:
            result = self._client.createfsip(ip,
                                             subnet,
                                             vfs,
                                             fpg=fpg,
                                             vlantag=vlantag_str)
            LOG.debug("createfsip result: %s", result)

        except Exception as e:
            LOG.exception(e)
            msg = (_('Failed to create FSIP for %s') % ip)
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

        # Verify that it really exists.
        fsip = {
            'fspool': fpg,
            'vfs': vfs,
            'address': ip,
            'prefixLen': subnet,
            'vlanTag': vlantag_str,
        }
        if not self.fsip_exists(fsip):
            msg = (_('Failed to get FSIP after creating it for '
                     'FPG/VFS/IP/subnet/VLAN '
                     '%(fspool)s/%(vfs)s/'
                     '%(address)s/%(prefixLen)s/%(vlanTag)s.') % fsip)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

    def remove_fsip(self, ip, fpg, vfs):

        if not (vfs and ip):
            # If there is no VFS and/or IP, then there is no FSIP to remove.
            return

        try:
            result = self._client.removefsip(vfs, ip, fpg=fpg)
            LOG.debug("removefsip result: %s", result)

        except Exception as e:
            LOG.exception(e)
            msg = (_('Failed to remove FSIP %s') % ip)
            LOG.exception(msg)
            raise exception.ShareBackendException(msg=msg)

        # Verify that it really no longer exists.
        fsip = {
            'fspool': fpg,
            'vfs': vfs,
            'address': ip,
        }
        if self.fsip_exists(fsip):
            msg = (_('Failed to remove FSIP for FPG/VFS/IP '
                     '%(fspool)s/%(vfs)s/%(address)s.') % fsip)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)
