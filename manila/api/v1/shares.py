# Copyright 2013 NetApp
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

"""The shares api."""

import webob
from webob import exc

from manila.api import common
from manila.api.openstack import wsgi
from manila.api.views import shares as share_views
from manila.api import xmlutil
from manila.common import constants
from manila import exception
from manila.openstack.common import log as logging
from manila import share


LOG = logging.getLogger(__name__)


def make_share(elem):
    attrs = ['id', 'size', 'availability_zone', 'status', 'name',
             'description', 'share_proto', 'export_location', 'links',
             'snapshot_id', 'created_at', 'metadata']
    for attr in attrs:
        elem.set(attr)


class ShareTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('share', selector='share')
        make_share(root)
        return xmlutil.MasterTemplate(root, 1)


class SharesTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('shares')
        elem = xmlutil.SubTemplateElement(root, 'share', selector='shares')
        make_share(elem)
        return xmlutil.MasterTemplate(root, 1)


class ShareController(wsgi.Controller):
    """The Shares API controller for the OpenStack API."""

    _view_builder_class = share_views.ViewBuilder

    def __init__(self):
        super(ShareController, self).__init__()
        self.share_api = share.API()

    @wsgi.serializers(xml=ShareTemplate)
    def show(self, req, id):
        """Return data about the given share."""
        context = req.environ['manila.context']

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        return self._view_builder.detail(req, share)

    def delete(self, req, id):
        """Delete a share."""
        context = req.environ['manila.context']

        LOG.audit(_("Delete share with id: %s"), id, context=context)

        try:
            share = self.share_api.get(context, id)
            self.share_api.delete(context, share)
        except exception.NotFound:
            raise exc.HTTPNotFound()
        except exception.InvalidShare:
            raise exc.HTTPForbidden()

        return webob.Response(status_int=202)

    @wsgi.serializers(xml=SharesTemplate)
    def index(self, req):
        """Returns a summary list of shares."""
        return self._get_shares(req, is_detail=False)

    @wsgi.serializers(xml=SharesTemplate)
    def detail(self, req):
        """Returns a detailed list of shares."""
        return self._get_shares(req, is_detail=True)

    def _get_shares(self, req, is_detail):
        """Returns a list of shares, transformed through view
           builder.
        """
        context = req.environ['manila.context']

        search_opts = {}
        search_opts.update(req.GET)

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if 'name' in search_opts:
            search_opts['display_name'] = search_opts['name']
            del search_opts['name']

        common.remove_invalid_options(
            context, search_opts, self._get_share_search_options())

        shares = self.share_api.get_all(context, search_opts=search_opts)

        limited_list = common.limited(shares, req)

        if is_detail:
            shares = self._view_builder.detail_list(req, limited_list)
        else:
            shares = self._view_builder.summary_list(req, limited_list)
        return shares

    def _get_share_search_options(self):
        """Return share search options allowed by non-admin."""
        return ('name', 'status')

    @wsgi.serializers(xml=ShareTemplate)
    def update(self, req, id, body):
        """Update a share."""
        context = req.environ['manila.context']

        if not body or 'share' not in body:
            raise exc.HTTPUnprocessableEntity()

        share_data = body['share']
        valid_update_keys = (
            'display_name',
            'display_description',
        )

        update_dict = dict([(key, share_data[key])
                            for key in valid_update_keys
                            if key in share_data])

        try:
            share = self.share_api.get(context, id)
        except exception.NotFound:
            raise exc.HTTPNotFound()

        share = self.share_api.update(context, share, update_dict)
        share.update(update_dict)
        return self._view_builder.detail(req, share)

    @wsgi.serializers(xml=ShareTemplate)
    def create(self, req, body):
        """Creates a new share."""
        context = req.environ['manila.context']

        if not self.is_valid_body(body, 'share'):
            raise exc.HTTPUnprocessableEntity()

        share = body['share']

        # NOTE(rushiagr): v2 API allows name instead of display_name
        if share.get('name'):
            share['display_name'] = share.get('name')
            del share['name']

        # NOTE(rushiagr): v2 API allows description instead of
        #                display_description
        if share.get('description'):
            share['display_description'] = share.get('description')
            del share['description']

        size = share['size']
        share_proto = share['share_proto'].upper()

        msg = (_("Create %(share_proto)s share of %(size)s GB") %
               {'share_proto': share_proto, 'size': size})
        LOG.audit(msg, context=context)

        kwargs = {}
        kwargs['availability_zone'] = share.get('availability_zone')

        kwargs['metadata'] = share.get('metadata', None)

        snapshot_id = share.get('snapshot_id')
        if snapshot_id:
            kwargs['snapshot'] = self.share_api.get_snapshot(context,
                                                             snapshot_id)
        else:
            kwargs['snapshot'] = None

        share_network_id = share.get('share_network_id')
        if share_network_id:
            try:
                share_network = self.share_api.db.share_network_get(
                                context,
                                share_network_id)
            except exception.ShareNetworkNotFound as e:
                msg = "%s" % e
                raise exc.HTTPNotFound(explanation=msg)
            if share_network['status'] != constants.STATUS_ACTIVE:
                msg = _("Share network '%s' is not in 'ACTIVE' state.")
                msg = msg % share_network["id"]
                raise exc.HTTPBadRequest(explanation=msg)
            else:
                kwargs['share_network_id'] = share_network_id

        display_name = share.get('display_name')
        display_description = share.get('display_description')
        new_share = self.share_api.create(context,
                                          share_proto,
                                          size,
                                          display_name,
                                          display_description,
                                          **kwargs)

        # TODO(vish): Instance should be None at db layer instead of
        #             trying to lazy load, but for now we turn it into
        #             a dict to avoid an error.
        return self._view_builder.summary(req, dict(new_share.iteritems()))


def create_resource():
    return wsgi.Resource(ShareController())
