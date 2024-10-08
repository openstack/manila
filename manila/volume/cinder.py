# Copyright 2014 Mirantis Inc.
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
Handles all requests relating to volumes + cinder.
"""

import copy

from cinderclient import exceptions as cinder_exception
from cinderclient.v3 import client as cinder_client
from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

from manila.common import client_auth
from manila.common.config import core_opts
import manila.context as ctxt
from manila.db import base
from manila import exception
from manila.i18n import _

CINDER_GROUP = 'cinder'
AUTH_OBJ = None

cinder_opts = [
    cfg.BoolOpt('cross_az_attach',
                default=True,
                help='Allow attaching between instances and volumes in '
                     'different availability zones.'),
    cfg.IntOpt('http_retries',
               default=3,
               help='Number of cinderclient retries on failed HTTP calls.'),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['publicURL', 'internalURL', 'adminURL',
                        'public', 'internal', 'admin'],
               help='Endpoint type to be used with cinder client calls.'),
    cfg.StrOpt('region_name',
               help='Region name for connecting to cinder.'),
    ]


CONF = cfg.CONF
CONF.register_opts(core_opts)
CONF.register_opts(cinder_opts, CINDER_GROUP)
ks_loading.register_session_conf_options(CONF,
                                         CINDER_GROUP)
ks_loading.register_auth_conf_options(CONF, CINDER_GROUP)


def list_opts():
    return client_auth.AuthClientLoader.list_opts(CINDER_GROUP)


def cinderclient(context):
    global AUTH_OBJ
    if not AUTH_OBJ:
        AUTH_OBJ = client_auth.AuthClientLoader(
            client_class=cinder_client.Client, cfg_group=CINDER_GROUP)
    return AUTH_OBJ.get_client(context,
                               retries=CONF[CINDER_GROUP].http_retries,
                               endpoint_type=CONF[CINDER_GROUP].endpoint_type,
                               region_name=CONF[CINDER_GROUP].region_name)


def _untranslate_volume_summary_view(context, vol):
    """Maps keys for volumes summary view."""
    d = {}
    d['id'] = vol.id
    d['status'] = vol.status
    d['size'] = vol.size
    d['availability_zone'] = vol.availability_zone
    d['created_at'] = vol.created_at

    d['attach_time'] = ""
    d['mountpoint'] = ""

    if vol.attachments:
        att = vol.attachments[0]
        d['attach_status'] = 'attached'
        d['instance_uuid'] = att['server_id']
        d['mountpoint'] = att['device']
    else:
        d['attach_status'] = 'detached'

    d['name'] = vol.name
    d['description'] = vol.description

    d['volume_type_id'] = vol.volume_type
    d['snapshot_id'] = vol.snapshot_id

    d['volume_metadata'] = {}
    for key, value in vol.metadata.items():
        d['volume_metadata'][key] = value

    if hasattr(vol, 'volume_image_metadata'):
        d['volume_image_metadata'] = copy.deepcopy(vol.volume_image_metadata)

    return d


def _untranslate_snapshot_summary_view(context, snapshot):
    """Maps keys for snapshots summary view."""
    d = {}

    d['id'] = snapshot.id
    d['status'] = snapshot.status
    d['progress'] = snapshot.progress
    d['size'] = snapshot.size
    d['created_at'] = snapshot.created_at
    d['name'] = snapshot.name
    d['description'] = snapshot.description
    d['volume_id'] = snapshot.volume_id
    d['project_id'] = snapshot.project_id
    d['volume_size'] = snapshot.size

    return d


def translate_volume_exception(method):
    """Transforms the exception for the volume, keeps its traceback intact."""
    def wrapper(self, ctx, volume_id, *args, **kwargs):
        try:
            res = method(self, ctx, volume_id, *args, **kwargs)
        except cinder_exception.ClientException as e:
            if isinstance(e, cinder_exception.NotFound):
                raise exception.VolumeNotFound(volume_id=volume_id)
            elif isinstance(e, cinder_exception.BadRequest):
                raise exception.InvalidInput(reason=str(e))
        return res
    return wrapper


def translate_snapshot_exception(method):
    """Transforms the exception for the snapshot.

    Note: Keeps its traceback intact.
    """
    def wrapper(self, ctx, snapshot_id, *args, **kwargs):
        try:
            res = method(self, ctx, snapshot_id, *args, **kwargs)
        except cinder_exception.ClientException as e:
            if isinstance(e, cinder_exception.NotFound):
                raise exception.VolumeSnapshotNotFound(snapshot_id=snapshot_id)
        return res
    return wrapper


class API(base.Base):
    """API for interacting with the volume manager."""
    @translate_volume_exception
    def get(self, context, volume_id):
        item = cinderclient(context).volumes.get(volume_id)
        return _untranslate_volume_summary_view(context, item)

    def get_all(self, context, search_opts={}):
        items = cinderclient(context).volumes.list(detailed=True,
                                                   search_opts=search_opts)
        rval = []

        for item in items:
            rval.append(_untranslate_volume_summary_view(context, item))

        return rval

    def check_attached(self, context, volume):
        """Raise exception if volume in use."""
        if volume['status'] != "in-use":
            msg = _("status must be 'in-use'")
            raise exception.InvalidVolume(msg)

    def check_attach(self, context, volume, instance=None):
        if volume['status'] != "available":
            msg = _("status must be 'available'")
            raise exception.InvalidVolume(msg)
        if volume['attach_status'] == "attached":
            msg = _("already attached")
            raise exception.InvalidVolume(msg)
        if instance and not CONF[CINDER_GROUP].cross_az_attach:
            if instance['availability_zone'] != volume['availability_zone']:
                msg = _("Instance and volume not in same availability_zone")
                raise exception.InvalidVolume(msg)

    def check_detach(self, context, volume):
        if volume['status'] == "available":
            msg = _("already detached")
            raise exception.InvalidVolume(msg)

    @translate_volume_exception
    def reserve_volume(self, context, volume_id):
        cinderclient(context).volumes.reserve(volume_id)

    @translate_volume_exception
    def unreserve_volume(self, context, volume_id):
        cinderclient(context).volumes.unreserve(volume_id)

    @translate_volume_exception
    def begin_detaching(self, context, volume_id):
        cinderclient(context).volumes.begin_detaching(volume_id)

    @translate_volume_exception
    def roll_detaching(self, context, volume_id):
        cinderclient(context).volumes.roll_detaching(volume_id)

    @translate_volume_exception
    def attach(self, context, volume_id, instance_uuid, mountpoint):
        cinderclient(context).volumes.attach(volume_id, instance_uuid,
                                             mountpoint)

    @translate_volume_exception
    def detach(self, context, volume_id):
        cinderclient(context).volumes.detach(volume_id)

    @translate_volume_exception
    def initialize_connection(self, context, volume_id, connector):
        return cinderclient(context).volumes.initialize_connection(volume_id,
                                                                   connector)

    @translate_volume_exception
    def terminate_connection(self, context, volume_id, connector):
        return cinderclient(context).volumes.terminate_connection(volume_id,
                                                                  connector)

    def create(self, context, size, name, description, snapshot=None,
               image_id=None, volume_type=None, metadata=None,
               availability_zone=None):

        if snapshot is not None:
            snapshot_id = snapshot['id']
        else:
            snapshot_id = None

        kwargs = dict(snapshot_id=snapshot_id,
                      name=name,
                      description=description,
                      volume_type=volume_type,
                      user_id=context.user_id,
                      project_id=context.project_id,
                      availability_zone=availability_zone,
                      metadata=metadata,
                      imageRef=image_id)

        try:
            item = cinderclient(context).volumes.create(size, **kwargs)
            return _untranslate_volume_summary_view(context, item)
        except cinder_exception.BadRequest as e:
            raise exception.InvalidInput(reason=str(e))
        except cinder_exception.NotFound:
            raise exception.NotFound(
                _("Error in creating cinder "
                  "volume. Cinder volume type %s not exist. Check parameter "
                  "cinder_volume_type in configuration file.") % volume_type)
        except Exception as e:
            raise exception.ManilaException(e)

    @translate_volume_exception
    def extend(self, context, volume_id, new_size):
        cinderclient(context).volumes.extend(volume_id, new_size)

    @translate_volume_exception
    def delete(self, context, volume_id):
        cinderclient(context).volumes.delete(volume_id)

    @translate_volume_exception
    def update(self, context, volume_id, fields):
        # Use Manila's context as far as Cinder's is restricted to update
        # volumes.
        manila_admin_context = ctxt.get_admin_context()
        client = cinderclient(manila_admin_context)
        item = client.volumes.get(volume_id)
        client.volumes.update(item, **fields)

    @translate_snapshot_exception
    def get_snapshot(self, context, snapshot_id):
        item = cinderclient(context).volume_snapshots.get(snapshot_id)
        return _untranslate_snapshot_summary_view(context, item)

    def get_all_snapshots(self, context, search_opts=None):
        items = cinderclient(context).volume_snapshots.list(
            detailed=True,
            search_opts=search_opts)
        rvals = []

        for item in items:
            rvals.append(_untranslate_snapshot_summary_view(context, item))

        return rvals

    @translate_volume_exception
    def create_snapshot(self, context, volume_id, name, description):
        item = cinderclient(context).volume_snapshots.create(volume_id,
                                                             False,
                                                             name,
                                                             description)
        return _untranslate_snapshot_summary_view(context, item)

    @translate_volume_exception
    def create_snapshot_force(self, context, volume_id, name, description):
        item = cinderclient(context).volume_snapshots.create(volume_id,
                                                             True,
                                                             name,
                                                             description)

        return _untranslate_snapshot_summary_view(context, item)

    @translate_snapshot_exception
    def delete_snapshot(self, context, snapshot_id):
        cinderclient(context).volume_snapshots.delete(snapshot_id)
