# Copyright (c) 2014 NetApp, Inc.
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
NetApp specific NAS storage driver. Supports NFS and CIFS protocols.

This driver requires one or more Data ONTAP 7-mode
storage systems with installed CIFS and NFS licenses.
"""

import os

from oslo.config import cfg

from manila import exception
from manila.openstack.common import log
from manila.share import driver
from manila.share.drivers.netapp import api as naapi

NETAPP_NAS_OPTS = [
    cfg.StrOpt('netapp_nas_transport_type',
               default='http',
               help='Transport type protocol.'),
    cfg.StrOpt('netapp_nas_login',
               default='admin',
               help='User name for the ONTAP controller.'),
    cfg.StrOpt('netapp_nas_password',
               help='Password for the ONTAP controller.',
               secret=True),
    cfg.StrOpt('netapp_nas_server_hostname',
               help='Hostname for the ONTAP controller.'),
    cfg.FloatOpt('netapp_nas_size_multiplier',
                 default=1.2,
                 help='Volume size multiplier to ensure while creation.'),
    cfg.StrOpt('netapp_nas_vfiler',
               help='Vfiler to use for provisioning.'),
    cfg.StrOpt('netapp_nas_volume_name_template',
               help='Netapp volume name template.',
               default='share_%(share_id)s'),
]

CONF = cfg.CONF
CONF.register_opts(NETAPP_NAS_OPTS)

LOG = log.getLogger(__name__)


class NetAppApiClient(object):

    def __init__(self, version, vfiler=None, vserver=None, *args, **kwargs):
        self.configuration = kwargs.get('configuration', None)
        if not self.configuration:
            raise exception.NetAppException(_("NetApp configuration missing."))
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "NetApp_7_Mode"
        self._client = naapi.NaServer(
            host=self.configuration.netapp_nas_server_hostname,
            username=self.configuration.netapp_nas_login,
            password=self.configuration.netapp_nas_password,
            transport_type=self.configuration.netapp_nas_transport_type)
        self._client.set_api_version(*version)
        if vfiler:
            self._client.set_vfiler(vfiler)
        if vserver:
            self._client.set_vserver(vserver)

    def send_request(self, api_name, args=None):
        """Sends request to Ontapi."""
        elem = naapi.NaElement(api_name)
        if args:
            elem.translate_struct(args)
        LOG.debug("NaElement: %s" % elem.to_string(pretty=True))
        return self._client.invoke_successfully(elem, enable_tunneling=True)


class NetAppShareDriver(driver.ShareDriver):
    """
    NetApp specific ONTAP 7-mode driver.

    Supports NFS and CIFS protocols.
    Uses Ontap devices as backend to create shares
    and snapshots.
    Does not support multi-tenancy.
    """

    ONTAP_LICENSES = ('NFS', 'CIFS', 'FlexClone')

    def __init__(self, db, *args, **kwargs):
        super(NetAppShareDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(NETAPP_NAS_OPTS)
        self.db = db
        self.api_version = (1, 7)
        self._helpers = None
        self._licenses = None
        self._client = None

    def do_setup(self, context):
        """Prepare once the driver.

        Called once by the manager after the driver is loaded.
        Sets up clients, check licenses, sets up protocol
        specific helpers.
        """
        self._client = NetAppApiClient(
            self.api_version, vfiler=self.configuration.netapp_nas_vfiler,
            configuration=self.configuration)
        self._setup_helpers()

    def check_for_setup_error(self):
        """Check if vfiler form config exists."""
        self._check_licenses()
        self._check_vfiler_exists()

    def create_share(self, context, share, share_server=None):
        """Creates container for new share and exports it."""
        self._allocate_container(share)
        return self._create_export(share)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        self._allocate_container_from_snapshot(share, snapshot)
        return self._create_export(share)

    def ensure_share(self, context, share, share_server=None):
        """"""
        pass

    def _allocate_container(self, share):
        """Allocate space for the share on aggregates."""
        self._allocate_share_space(share)

    def _allocate_container_from_snapshot(self, share, snapshot):
        """Creates clone from existing share."""
        share_name = self._get_valid_share_name(share['id'])
        parent_share_name = self._get_valid_share_name(snapshot['share_id'])
        parent_snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        LOG.debug('Creating volume from snapshot %s' % snapshot['id'])
        args = {'volume': share_name,
                'parent-volume': parent_share_name,
                'parent-snapshot': parent_snapshot_name}

        self._client.send_request('volume-clone-create', args)

    def delete_share(self, context, share, share_server=None):
        """Deletes share."""
        share_name = self._get_valid_share_name(share['id'])
        if self._share_exists(share_name):
            self._remove_export(share)
            self._deallocate_container(share)
        else:
            LOG.info(_("Share %s does not exists") % share['id'])

    def _share_exists(self, share_name):
        args = {'volume': share_name}
        try:
            self._client.send_request('volume-list-info', args)
            return True
        except naapi.NaApiError as e:
            if e.code == "13040":
                LOG.debug("Share %s does not exists" % share_name)
                return False

    def _deallocate_container(self, share):
        """Free share space."""
        self._offline_share(share)
        self._delete_share(share)

    def _create_export(self, share):
        """Creates export accordingly to share protocol."""
        helper = self._get_helper(share)
        share_name = self._get_valid_share_name(share['id'])
        export_location = helper.create_share(
            share_name, self.configuration.netapp_nas_server_hostname)
        return export_location

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])
        args = {'volume': share_name,
                'snapshot': snapshot_name}
        LOG.debug('Creating snapshot %s' % snapshot_name)
        self._client.send_request('snapshot-create', args)

    def _remove_export(self, share):
        """Deletes NAS storage."""
        helper = self._get_helper(share)
        target = helper.get_target(share)
        # share may be in error state, so there's no share and target
        if target:
            helper.delete_share(share)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""
        share_name = self._get_valid_share_name(snapshot['share_id'])
        snapshot_name = self._get_valid_snapshot_name(snapshot['id'])

        if self._is_snapshot_busy(share_name, snapshot_name):
            raise exception.ShareSnapshotIsBusy(snapshot_name=snapshot_name)
        args = {'snapshot': snapshot_name,
                'volume': share_name}

        LOG.debug('Deleting snapshot %s' % snapshot_name)
        self._client.send_request('snapshot-delete', args)

    def allow_access(self, context, share, access, share_server=None):
        """Allows access to a given NAS storage for IPs in access."""
        helper = self._get_helper(share)
        return helper.allow_access(context, share, access)

    def deny_access(self, context, share, access, share_server=None):
        """Denies access to a given NAS storage for IPs in access."""
        helper = self._get_helper(share)
        return helper.deny_access(context, share, access)

    def _check_vfiler_exists(self):
        vfiler_status = self._client.send_request('vfiler-get-status',
                {'vfiler': self.configuration.netapp_nas_vfiler})
        if vfiler_status.get_child_content('status') != 'running':
            msg = _("Vfiler %s is not running") \
                  % self.configuration.netapp_nas_vfiler
            LOG.error(msg)
            raise exception.NetAppException(msg)

    def _check_licenses(self):
        try:
            licenses = self._client.send_request('license-v2-list-info')
        except naapi.NaApiError:
            licenses = self._client.send_request('license-list-info')
        self._licenses = [l.get_child_content('package').lower() for l in
                licenses.get_child_by_name('licenses').get_children()]
        LOG.info(_("Available licenses: %s") % ', '.join(self._licenses))
        return self._licenses

    def _offline_share(self, share):
        """Sends share offline. Required before deleting a share."""
        share_name = self._get_valid_share_name(share['id'])
        args = {'name': share_name}
        LOG.debug('Offline volume %s' % share_name)
        self._client.send_request('volume-offline', args)

    def _delete_share(self, share):
        """Destroys share on a target OnTap device."""
        share_name = self._get_valid_share_name(share['id'])
        args = {'name': share_name}
        LOG.debug('Deleting share %s' % share_name)
        self._client.send_request('volume-destroy', args)

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {'CIFS': NetAppCIFSHelper(),
                         'NFS': NetAppNFSHelper()}
        for helper in self._helpers.values():
            helper.set_client(self._client)

    def _get_helper(self, share):
        """Returns driver which implements share protocol."""
        share_proto = share['share_proto']
        if share_proto.lower() not in self._licenses:
            current_licenses = self._check_licenses()
            if share_proto not in current_licenses:
                msg = _("There is no license for %s at Ontap") % share_proto
                LOG.error(msg)
                raise exception.NetAppException(msg)

        for proto in self._helpers.keys():
            if share_proto.upper().startswith(proto):
                return self._helpers[proto]

        err_msg = _("Invalid NAS protocol supplied: %s. ") % share_proto

        raise exception.NetAppException(err_msg)

    def get_available_aggregates(self):
        """Returns aggregate list for the vfiler."""
        LOG.debug('Finding available aggreagates for vfiler')
        response = self._client.send_request('aggr-list-info')
        aggr_list_elements = response.get_child_by_name('aggregates')\
            .get_children()

        if not aggr_list_elements:
            msg = _("No aggregate assigned to vfiler %s")\
                  % self.configuration.netapp_nas_vfiler
            LOG.error(msg)
            raise exception.NetAppException(msg)

        # return dict of key-value pair of aggr_name:size
        aggr_dict = {}

        for aggr_elem in aggr_list_elements:
            aggr_name = aggr_elem.get_child_content('name')
            aggr_size = int(aggr_elem.get_child_content('size-available'))
            aggr_dict[aggr_name] = aggr_size
        LOG.debug("Found available aggregates: %r" % aggr_dict)
        return aggr_dict

    def _allocate_share_space(self, share):
        """Create new share on aggregate."""
        share_name = self._get_valid_share_name(share['id'])
        aggregates = self.get_available_aggregates()
        aggregate = max(aggregates, key=lambda m: aggregates[m])
        LOG.debug('Creating volume %(share)s on aggregate %(aggr)s'
                  % {'share': share_name, 'aggr': aggregate})
        args = {'containing-aggr-name': aggregate,
                'size': str(share['size']) + 'g',
                'volume': share_name,
                }
        self._client.send_request('volume-create', args)

    def _is_snapshot_busy(self, share_name, snapshot_name):
        """Raises ShareSnapshotIsBusy if snapshot is busy."""
        args = {'volume': share_name}
        snapshots = self._client.send_request('snapshot-list-info', args)
        snapshots = snapshots.get_child_by_name('snapshots')
        if snapshots:
            for snap in snapshots.get_children():
                if snap.get_child_content('name') == snapshot_name \
                    and snap.get_child_content('busy') == 'true':
                        return True

    def _get_valid_share_name(self, share_id):
        """Get share name according to share name template."""
        return self.configuration.netapp_nas_volume_name_template %\
               {'share_id': share_id.replace('-', '_')}

    def _get_valid_snapshot_name(self, snapshot_id):
        """Get snapshot name according to snapshot name template."""
        return 'share_snapshot_' + snapshot_id.replace('-', '_')

    def _update_share_status(self):
        """Retrieve status info from share volume group."""

        LOG.debug("Updating share status")
        data = {}

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = self.backend_name
        data["vendor_name"] = 'NetApp'
        data["driver_version"] = '1.0'
        #TODO(rushiagr): Pick storage_protocol from the helper used.
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'
        data['reserved_percentage'] = 0
        data['QoS_support'] = False

        self._stats = data

    def get_network_allocations_number(self):
        """7mode driver does not need to create VIFS."""
        return 0

    def setup_network(self, network_info, metadata=None):
        """Nothing to set up"""
        pass


class NetAppNASHelperBase(object):
    """Interface for protocol-specific NAS drivers."""
    def __init__(self):
        self._client = None

    def set_client(self, client):
        self._client = client

    def create_share(self, share, export_ip):
        """Creates NAS share."""
        raise NotImplementedError()

    def delete_share(self, share):
        """Deletes NAS share."""
        raise NotImplementedError()

    def allow_access(self, context, share, new_rules):
        """Allows new_rules to a given NAS storage for IPs in new_rules."""
        raise NotImplementedError()

    def deny_access(self, context, share, new_rules):
        """Denies new_rules to a given NAS storage for IPs in new_rules."""
        raise NotImplementedError()

    def get_target(self, share):
        """Returns host where the share located."""
        raise NotImplementedError()


class NetAppNFSHelper(NetAppNASHelperBase):
    """Netapp specific NFS sharing driver."""
    def add_rules(self, volume_path, rules):
        security_rule_args = {
            'security-rule-info': {
                'read-write': {
                    'exports-hostname-info': {
                        'name': 'localhost'
                    }
                },
                'root': {
                    'exports-hostname-info': {
                        'all-hosts': 'false',
                        'name': 'localhost'
                    }
                }
            }
        }
        hostname_info_args = {
            'exports-hostname-info': {
                'name': 'localhost'
            }
        }
        args = {
            'rules': {
                'exports-rule-info-2': {
                    'pathname': volume_path,
                    'security-rules': {
                        'security-rule-info': {
                            'read-write': {
                                'exports-hostname-info': {
                                    'name': 'localhost'
                                }
                            },
                            'root': {
                                'exports-hostname-info': {
                                    'all-hosts': 'false',
                                    'name': 'localhost'
                                }
                            }
                        }
                    }
                }
            }
        }
        allowed_hosts_xml = []

        for ip in rules:
            hostname_info = hostname_info_args.copy()
            hostname_info['exports-hostname-info'] = {'name': ip}
            allowed_hosts_xml.append(hostname_info)

        security_rule = security_rule_args.copy()
        security_rule['security-rule-info']['read-write'] = allowed_hosts_xml
        security_rule['security-rule-info']['root'] = allowed_hosts_xml

        args['rules']['exports-rule-info-2']['security-rules'] = security_rule

        LOG.debug('Appending nfs rules %r' % rules)
        self._client.send_request('nfs-exportfs-append-rules-2',
                                               args)

    def create_share(self, share_name, export_ip):
        """Creates NFS share."""
        export_pathname = os.path.join('/vol', share_name)
        self.add_rules(export_pathname, ['127.0.0.1'])

        export_location = ':'.join([export_ip, export_pathname])
        return export_location

    def delete_share(self, share):
        """Deletes NFS share."""
        target, export_path = self._get_export_path(share)

        args = {
            'pathnames': {
                'pathname-info': {
                    'name': export_path
                }
            }
        }
        LOG.debug('Deleting NFS rules for share %s' % share['id'])
        self._client.send_request('nfs-exportfs-delete-rules', args)

    def allow_access(self, context, share, access):
        """Allows access to a given NFS storage for IPs in access."""
        if access['access_type'] != 'ip':
            raise exception.NetAppException(_('7mode driver supports only'
                                              ' \'ip\' type'))

        new_rules = access['access_to']
        existing_rules = self._get_exisiting_rules(share)
        if not isinstance(new_rules, list):
            new_rules = [new_rules]
        rules = existing_rules + new_rules
        try:
            self._modify_rule(share, rules)
        except naapi.NaApiError:
            self._modify_rule(share, existing_rules)

    def deny_access(self, context, share, access):
        """Denies access to a given NFS storage for IPs in access."""
        denied_ips = access['access_to']
        existing_rules = self._get_exisiting_rules(share)

        if type(denied_ips) is not list:
            denied_ips = [denied_ips]

        for deny_rule in denied_ips:
            try:
                existing_rules.remove(deny_rule)
            except ValueError:
                pass

        self._modify_rule(share, existing_rules)

    def get_target(self, share):
        """Returns ID of target OnTap device based on export location."""
        return self._get_export_path(share)[0]

    def _modify_rule(self, share, rules):
        """Modifies access rule for a share."""
        target, export_path = self._get_export_path(share)
        self.add_rules(export_path, rules)

    def _get_exisiting_rules(self, share):
        """Returns available access rules for the share."""
        target, export_path = self._get_export_path(share)

        args = {'pathname': export_path}
        response = self._client.send_request('nfs-exportfs-list-rules-2', args)
        rules = response.get_child_by_name('rules')
        allowed_hosts = []
        if rules and rules.get_child_by_name('exports-rule-info-2'):
            security_rule = rules.get_child_by_name('exports-rule-info-2')\
                .get_child_by_name('security-rules')
            security_info = security_rule.get_child_by_name(
                'security-rule-info')
            if security_info:
                root_rules = security_info.get_child_by_name('root')
                if root_rules:
                    allowed_hosts = root_rules.get_children()

        existing_rules = []

        for allowed_host in allowed_hosts:
            if 'exports-hostname-info' in allowed_host.get_name():
                existing_rules.append(allowed_host.get_child_content('name'))
        LOG.debug('Found existing rules %(rules)r for share %(share)s'
                  % {'rules': existing_rules, 'share': share['id']})

        return existing_rules

    @staticmethod
    def _get_export_path(share):
        """Returns IP address and export location of a share."""
        export_location = share['export_location']

        if export_location is None:
            export_location = ':'

        return export_location.split(':')


class NetAppCIFSHelper(NetAppNASHelperBase):
    """Netapp specific CIFS sharing driver."""

    CIFS_USER_GROUP = 'Administrators'

    def create_share(self, share_name, export_ip):
        """Creates CIFS storage."""
        cifs_status = self._get_cifs_status()

        if cifs_status == 'stopped':
            self._start_cifs_service()

        self._set_qtree_security(share_name)
        self._add_share(share_name)
        self._restrict_access('everyone', share_name)

        cifs_location = self._set_export_location(
            export_ip, share_name)

        return cifs_location

    def delete_share(self, share):
        """Deletes CIFS storage."""
        host_ip, share_name = self._get_export_location(share)
        args = {'share-name': share_name}
        self._client.send_request('cifs-share-delete', args)

    def allow_access(self, context, share, access):
        """Allows access to a given CIFS storage for IPs in access."""
        if access['access_type'] != 'sid':
            msg = _('NetApp only supports "sid" access type for CIFS.')
            raise exception.NetAppException(msg)

        user = access['access_to']
        target, share_name = self._get_export_location(share)

        self._allow_access_for(user, share_name)

    def deny_access(self, context, share, access):
        """Denies access to a given CIFS storage for IPs in access."""
        host_ip, share_name = self._get_export_location(share)
        user = access['access_to']

        try:
            self._restrict_access(user, share_name)
        except naapi.NaApiError as e:
            if e.code == "22":
                LOG.error(_("User %s does not exist") % user)
            elif e.code == "15661":
                LOG.error(_("Rule %s does not exist") % user)
            else:
                raise e

    def get_target(self, share):
        """Returns OnTap target IP based on share export location."""
        return self._get_export_location(share)[0]

    def _set_qtree_security(self, share_name):
        share_name = '/vol/%s' % share_name

        args = {
            'args': [
                {'arg': 'qtree'},
                {'arg': 'security'},
                {'arg': share_name},
                {'arg': 'mixed'}
            ]
        }

        self._client.send_request('system-cli', args)

    def _restrict_access(self, user_name, share_name):
        args = {'user-name': user_name,
                'share-name': share_name}
        self._client.send_request('cifs-share-ace-delete', args)

    def _start_cifs_service(self):
        """Starts CIFS service on OnTap target."""
        self._client.send_request('cifs-start')

    @staticmethod
    def _get_export_location(share):
        """Returns export location for a given CIFS share."""
        export_location = share['export_location']

        if export_location is None:
            export_location = '///'

        _x, _x, host_ip, share_name = export_location.split('/')
        return host_ip, share_name

    @staticmethod
    def _set_export_location(ip, share_name):
        """Returns export location of a share."""
        return "//%s/%s" % (ip, share_name)

    def _get_cifs_status(self):
        """Returns status of a CIFS service on target OnTap."""
        response = self._client.send_request('cifs-status')
        return response.get_child_content('status')

    def _allow_access_for(self, username, share_name):
        """Allows access to the CIFS share for a given user."""
        args = {'access-rights': 'rwx',
                'share-name': share_name,
                'user-name': username}
        self._client.send_request('cifs-share-ace-set', args)

    def _add_share(self, share_name):
        """Creates CIFS share on target OnTap host."""
        share_path = '/vol/%s' % share_name
        args = {'path': share_path,
                'share-name': share_name}
        self._client.send_request('cifs-share-add', args)
