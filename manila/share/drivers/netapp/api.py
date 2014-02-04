# Copyright 2012 NetApp
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
import suds
from suds.sax import text

from manila import exception
from manila.openstack.common import log

from oslo.config import cfg


LOG = log.getLogger(__name__)
CONF = cfg.CONF


class NetAppApiClient(object):
    """Wrapper around DFM commands."""

    REQUIRED_FLAGS = ['netapp_nas_wsdl_url',
                      'netapp_nas_login',
                      'netapp_nas_password',
                      'netapp_nas_server_hostname',
                      'netapp_nas_server_port']

    def __init__(self, configuration):
        self.configuration = configuration
        self._client = None

    def do_setup(self):
        """Setup suds (web services) client."""
        protocol = 'https' if self.configuration.netapp_nas_server_secure \
            else 'http'
        soap_url = ('%s://%s:%s/apis/soap/v1' %
                    (protocol,
                     self.configuration.netapp_nas_server_hostname,
                     self.configuration.netapp_nas_server_port))

        self._client = \
            suds.client.Client(self.configuration.netapp_nas_wsdl_url,
                               username=self.configuration.netapp_nas_login,
                               password=self.configuration.netapp_nas_password,
                               location=soap_url)

        LOG.info('NetApp RPC client started')

    def send_request_to(self, target, request, xml_args=None,
                        do_response_check=True):
        """
        Sends RPC :request: to :target:.
        :param target: IP address, ID or network name of OnTap device
        :param request: API name
        :param xml_args: call arguments
        :param do_response_check: if set to True and RPC call has failed,
        raises exception.
        """
        client = self._client
        srv = client.service

        rpc = client.factory.create('Request')
        rpc.Name = request
        rpc.Args = text.Raw(xml_args)
        response = srv.ApiProxy(Request=rpc, Target=target)

        if do_response_check:
            _check_response(rpc, response)

        return response

    def get_available_aggregates(self):
        """Returns list of aggregates known by DFM."""
        srv = self._client.service
        resp = srv.AggregateListInfoIterStart()
        tag = resp.Tag

        try:
            avail_aggrs = srv.AggregateListInfoIterNext(Tag=tag,
                                                        Maximum=resp.Records)
        finally:
            srv.AggregateListInfoIterEnd(tag)

        return avail_aggrs

    def get_host_ip_by(self, host_id):
        """Returns IP address of a host known by DFM."""
        if (type(host_id) is str or type(host_id) is unicode) and \
                len(host_id.split('.')) == 4:
            # already IP
            return host_id

        client = self._client
        srv = client.service

        filer_filter = client.factory.create('HostListInfoIterStart')
        filer_filter.ObjectNameOrId = host_id
        resp = srv.HostListInfoIterStart(HostListInfoIterStart=filer_filter)
        tag = resp.Tag

        try:
            filers = srv.HostListInfoIterNext(Tag=tag, Maximum=resp.Records)
        finally:
            srv.HostListInfoIterEnd(Tag=tag)

        ip = None
        for host in filers.Hosts.HostInfo:
            if int(host.HostId) == int(host_id):
                ip = host.HostAddress

        return ip

    @staticmethod
    def check_configuration(config_object):
        """Ensure that the flags we care about are set."""
        for flag in NetAppApiClient.REQUIRED_FLAGS:
            if not getattr(config_object, flag, None):
                raise exception.Error(_('%s is not set') % flag)
