# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2014 Clinton Knight.  All rights reserved.
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

from oslo_log import log
from oslo_utils import excutils

from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppBaseClient(object):

    def __init__(self, **kwargs):
        self.connection = netapp_api.NaServer(
            host=kwargs['hostname'],
            transport_type=kwargs['transport_type'],
            port=kwargs['port'],
            username=kwargs['username'],
            password=kwargs['password'],
            trace=kwargs.get('trace', False),
            api_trace_pattern=kwargs.get('api_trace_pattern',
                                         na_utils.API_TRACE_PATTERN))

    def get_ontapi_version(self, cached=True):
        """Gets the supported ontapi version."""

        if cached:
            return self.connection.get_api_version()

        result = self.send_request('system-get-ontapi-version',
                                   enable_tunneling=False)
        major = result.get_child_content('major-version')
        minor = result.get_child_content('minor-version')
        return major, minor

    @na_utils.trace
    def get_system_version(self, cached=True):
        """Gets the current Data ONTAP version."""

        if cached:
            return self.connection.get_system_version()

        result = self.send_request('system-get-version')

        version_tuple = result.get_child_by_name(
            'version-tuple') or netapp_api.NaElement('none')
        system_version_tuple = version_tuple.get_child_by_name(
            'system-version-tuple') or netapp_api.NaElement('none')

        version = {}
        version['version'] = result.get_child_content('version')
        version['version-tuple'] = (
            int(system_version_tuple.get_child_content('generation')),
            int(system_version_tuple.get_child_content('major')),
            int(system_version_tuple.get_child_content('minor')))

        return version

    def _init_features(self):
        """Set up the repository of available Data ONTAP features."""
        self.features = Features()

    def _strip_xml_namespace(self, string):
        if string.startswith('{') and '}' in string:
            return string.split('}', 1)[1]
        return string

    def send_request(self, api_name, api_args=None, enable_tunneling=True):
        """Sends request to Ontapi."""
        request = netapp_api.NaElement(api_name)
        if api_args:
            request.translate_struct(api_args)
        return self.connection.invoke_successfully(request, enable_tunneling)

    @na_utils.trace
    def get_licenses(self):
        try:
            result = self.send_request('license-v2-list-info')
        except netapp_api.NaApiError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Could not get licenses list.")

        return sorted(
            [l.get_child_content('package').lower()
             for l in result.get_child_by_name('licenses').get_children()])

    def send_ems_log_message(self, message_dict):
        """Sends a message to the Data ONTAP EMS log."""
        raise NotImplementedError()


class Features(object):

    def __init__(self):
        self.defined_features = set()

    def add_feature(self, name, supported=True):
        if not isinstance(supported, bool):
            raise TypeError("Feature value must be a bool type.")
        self.defined_features.add(name)
        setattr(self, name, supported)

    def __getattr__(self, name):
        # NOTE(cknight): Needed to keep pylint happy.
        raise AttributeError
