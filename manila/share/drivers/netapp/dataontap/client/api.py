# Copyright (c) 2014 Navneet Singh.  All rights reserved.
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
"""
NetApp API for Data ONTAP and OnCommand DFM.

Contains classes required to issue API calls to Data ONTAP and OnCommand DFM.
"""

import copy
import re

from lxml import etree
from oslo_log import log
from oslo_serialization import jsonutils
import requests
from requests.adapters import HTTPAdapter
from requests import auth
from requests.packages.urllib3.util.retry import Retry

from manila import exception
from manila.i18n import _
from manila.share.drivers.netapp.dataontap.client import rest_endpoints
from manila.share.drivers.netapp import utils

LOG = log.getLogger(__name__)

EONTAPI_EINVAL = '22'
EVOLOPNOTSUPP = '160'
EAPIERROR = '13001'
EAPINOTFOUND = '13005'
ESNAPSHOTNOTALLOWED = '13023'
EVOLUMEOFFLINE = '13042'
EINTERNALERROR = '13114'
EINVALIDINPUTERROR = '13115'
EDUPLICATEENTRY = '13130'
EVOLNOTCLONE = '13170'
EVOLMOVE_CANNOT_MOVE_TO_CFO = '13633'
EAGGRDOESNOTEXIST = '14420'
EVOL_NOT_MOUNTED = '14716'
EVSERVERALREADYSTARTED = '14923'
ESIS_CLONE_NOT_LICENSED = '14956'
EOBJECTNOTFOUND = '15661'
EVSERVERNOTFOUND = '15698'
E_VIFMGR_PORT_ALREADY_ASSIGNED_TO_BROADCAST_DOMAIN = '18605'
ERELATION_EXISTS = '17122'
ENOTRANSFER_IN_PROGRESS = '17130'
ETRANSFER_IN_PROGRESS = '17137'
EANOTHER_OP_ACTIVE = '17131'
ERELATION_NOT_QUIESCED = '17127'
ESOURCE_IS_DIFFERENT = '17105'
EVOL_CLONE_BEING_SPLIT = '17151'
EPOLICYNOTFOUND = '18251'
EEVENTNOTFOUND = '18253'
ESCOPENOTFOUND = '18259'
ESVMDR_CANNOT_PERFORM_OP_FOR_STATUS = '18815'
ENFS_V4_0_ENABLED_MIGRATION_FAILURE = '13172940'
EVSERVER_MIGRATION_TO_NON_AFF_CLUSTER = '13172984'

STYLE_LOGIN_PASSWORD = 'basic_auth'
TRANSPORT_TYPE_HTTP = 'http'
TRANSPORT_TYPE_HTTPS = 'https'
STYLE_CERTIFICATE = 'certificate_auth'


class BaseClient(object):
    """Encapsulates server connection logic."""

    def __init__(self, host, transport_type=TRANSPORT_TYPE_HTTP, style=None,
                 ssl_cert_path=None, username=None, password=None, port=None,
                 trace=False, api_trace_pattern=None):
        super(BaseClient, self).__init__()
        self._host = host
        self.set_transport_type(transport_type)
        self.set_style(style)
        if port:
            self.set_port(port)
        self._username = username
        self._password = password
        self._trace = trace
        self._api_trace_pattern = api_trace_pattern
        self._refresh_conn = True
        if ssl_cert_path is not None:
            self._ssl_verify = ssl_cert_path
        else:
            # Note(felipe_rodrigues): it will verify with the mozila CA roots,
            # given by certifi package.
            self._ssl_verify = True
        LOG.debug('Using NetApp controller: %s', self._host)

    def get_style(self):
        """Get the authorization style for communicating with the server."""
        return self._auth_style

    def set_style(self, style):
        """Set the authorization style for communicating with the server.

        Supports basic_auth for now. Certificate_auth mode to be done.
        """
        if style.lower() not in (STYLE_LOGIN_PASSWORD, STYLE_CERTIFICATE):
            raise ValueError('Unsupported authentication style')
        self._auth_style = style.lower()

    def get_transport_type(self):
        """Get the transport type protocol."""
        return self._protocol

    def set_transport_type(self, transport_type):
        """Set the transport type protocol for API.

        Supports http and https transport types.
        """
        if transport_type.lower() not in (
                TRANSPORT_TYPE_HTTP, TRANSPORT_TYPE_HTTPS):
            raise ValueError('Unsupported transport type')
        self._protocol = transport_type.lower()
        self._refresh_conn = True

    def get_server_type(self):
        """Get the server type."""
        return self._server_type

    def set_server_type(self, server_type):
        """Set the target server type.

        Supports filer and dfm server types.
        """
        raise NotImplementedError()

    def set_api_version(self, major, minor):
        """Set the API version."""
        try:
            self._api_major_version = int(major)
            self._api_minor_version = int(minor)
            self._api_version = (str(major) + "." +
                                 str(minor))
        except ValueError:
            raise ValueError('Major and minor versions must be integers')
        self._refresh_conn = True

    def set_system_version(self, system_version):
        """Set the ONTAP system version."""
        self._system_version = system_version
        self._refresh_conn = True

    def get_api_version(self):
        """Gets the API version tuple."""
        if hasattr(self, '_api_version'):
            return (self._api_major_version, self._api_minor_version)
        return None

    def get_system_version(self):
        """Gets the ONTAP system version."""
        if hasattr(self, '_system_version'):
            return self._system_version
        return None

    def set_port(self, port):
        """Set the server communication port."""
        try:
            int(port)
        except ValueError:
            raise ValueError('Port must be integer')
        self._port = str(port)
        self._refresh_conn = True

    def get_port(self):
        """Get the server communication port."""
        return self._port

    def set_timeout(self, seconds):
        """Sets the timeout in seconds."""
        try:
            self._timeout = int(seconds)
        except ValueError:
            raise ValueError('timeout in seconds must be integer')

    def get_timeout(self):
        """Gets the timeout in seconds if set."""
        if hasattr(self, '_timeout'):
            return self._timeout
        return None

    def get_vserver(self):
        """Get the vserver to use in tunneling."""
        return self._vserver

    def set_vserver(self, vserver):
        """Set the vserver to use if tunneling gets enabled."""
        self._vserver = vserver

    def set_username(self, username):
        """Set the user name for authentication."""
        self._username = username
        self._refresh_conn = True

    def set_password(self, password):
        """Set the password for authentication."""
        self._password = password
        self._refresh_conn = True

    def invoke_successfully(self, na_element, api_args=None,
                            enable_tunneling=False, use_zapi=True):
        """Invokes API and checks execution status as success.

        Need to set enable_tunneling to True explicitly to achieve it.
        This helps to use same connection instance to enable or disable
        tunneling. The vserver or vfiler should be set before this call
        otherwise tunneling remains disabled.
        """
        pass

    def _build_session(self):
        """Builds a session in the client."""
        if self._auth_style == STYLE_LOGIN_PASSWORD:
            auth_handler = self._create_basic_auth_handler()
        else:
            auth_handler = self._create_certificate_auth_handler()

        self._session = requests.Session()

        max_retries = Retry(total=5, connect=5, read=2, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=max_retries)
        self._session.mount('%s://' % self._protocol, adapter)

        self._session.auth = auth_handler
        self._session.verify = self._ssl_verify
        headers = self._build_headers()

        self._session.headers = headers

    def _build_headers(self):
        """Adds the necessary headers to the session."""
        raise NotImplementedError()

    def _create_basic_auth_handler(self):
        """Creates and returns a basic HTTP auth handler."""
        return auth.HTTPBasicAuth(self._username, self._password)

    def _create_certificate_auth_handler(self):
        """Creates and returns a certificate auth handler."""
        raise NotImplementedError()

    def __str__(self):
        """Gets a representation of the client."""
        return "server: %s" % (self._host)


class ZapiClient(BaseClient):

    SERVER_TYPE_FILER = 'filer'
    SERVER_TYPE_DFM = 'dfm'
    URL_FILER = 'servlets/netapp.servlets.admin.XMLrequest_filer'
    URL_DFM = 'apis/XMLrequest'
    NETAPP_NS = 'http://www.netapp.com/filer/admin'

    def __init__(self, host, server_type=SERVER_TYPE_FILER,
                 transport_type=TRANSPORT_TYPE_HTTP,
                 style=STYLE_LOGIN_PASSWORD, ssl_cert_path=None, username=None,
                 password=None, port=None, trace=False,
                 api_trace_pattern=utils.API_TRACE_PATTERN):
        super(ZapiClient, self).__init__(
            host, transport_type=transport_type, style=style,
            ssl_cert_path=ssl_cert_path, username=username, password=password,
            port=port, trace=trace, api_trace_pattern=api_trace_pattern)
        self.set_server_type(server_type)
        if port is None:
            # Not yet set in parent, use defaults
            self._set_port()

    def _set_port(self):
        """Defines which port will be used to communicate with ONTAP."""
        if self._protocol == TRANSPORT_TYPE_HTTP:
            if self._server_type == ZapiClient.SERVER_TYPE_FILER:
                self.set_port(80)
            else:
                self.set_port(8088)
        else:
            if self._server_type == ZapiClient.SERVER_TYPE_FILER:
                self.set_port(443)
            else:
                self.set_port(8488)

    def set_server_type(self, server_type):
        """Set the target server type.

        Supports filer and dfm server types.
        """
        if server_type.lower() not in (ZapiClient.SERVER_TYPE_FILER,
                                       ZapiClient.SERVER_TYPE_DFM):
            raise ValueError('Unsupported server type')
        self._server_type = server_type.lower()
        if self._server_type == ZapiClient.SERVER_TYPE_FILER:
            self._url = ZapiClient.URL_FILER
        else:
            self._url = ZapiClient.URL_DFM
        self._ns = ZapiClient.NETAPP_NS
        self._refresh_conn = True

    def get_vfiler(self):
        """Get the vfiler to use in tunneling."""
        return self._vfiler

    def set_vfiler(self, vfiler):
        """Set the vfiler to use if tunneling gets enabled."""
        self._vfiler = vfiler

    def invoke_elem(self, na_element, enable_tunneling=False):
        """Invoke the API on the server."""
        if na_element and not isinstance(na_element, NaElement):
            ValueError('NaElement must be supplied to invoke API')

        request_element = self._create_request(na_element, enable_tunneling)
        request_d = request_element.to_string()

        api_name = na_element.get_name()
        api_name_matches_regex = (re.match(self._api_trace_pattern, api_name)
                                  is not None)

        if self._trace and api_name_matches_regex:
            LOG.debug("Request: %s", request_element.to_string(pretty=True))

        if (not hasattr(self, '_session') or not self._session
                or self._refresh_conn):
            self._build_session()
        try:
            if hasattr(self, '_timeout'):
                if self._timeout is None:
                    self._timeout = 10
                response = self._session.post(
                    self._get_url(), data=request_d, timeout=self._timeout)
            else:
                response = self._session.post(
                    self._get_url(), data=request_d)
        except requests.HTTPError as e:
            raise NaApiError(e.errno, e.strerror)
        except requests.URLRequired as e:
            raise exception.StorageCommunicationException(str(e))
        except Exception as e:
            raise NaApiError(message=e)

        response_xml = response.text
        response_element = self._get_result(
            bytes(bytearray(response_xml, encoding='utf-8')))

        if self._trace and api_name_matches_regex:
            LOG.debug("Response: %s", response_element.to_string(pretty=True))

        return response_element

    def invoke_successfully(self, na_element, api_args=None,
                            enable_tunneling=False, use_zapi=True):
        """Invokes API and checks execution status as success.

        Need to set enable_tunneling to True explicitly to achieve it.
        This helps to use same connection instance to enable or disable
        tunneling. The vserver or vfiler should be set before this call
        otherwise tunneling remains disabled.
        """
        if api_args:
            na_element.translate_struct(api_args)

        result = self.invoke_elem(
            na_element, enable_tunneling=enable_tunneling)

        if result.has_attr('status') and result.get_attr('status') == 'passed':
            return result
        code = (result.get_attr('errno')
                or result.get_child_content('errorno')
                or 'ESTATUSFAILED')
        if code == ESIS_CLONE_NOT_LICENSED:
            msg = 'Clone operation failed: FlexClone not licensed.'
        else:
            msg = (result.get_attr('reason')
                   or result.get_child_content('reason')
                   or 'Execution status is failed due to unknown reason')
        raise NaApiError(code, msg)

    def _create_request(self, na_element, enable_tunneling=False):
        """Creates request in the desired format."""
        netapp_elem = NaElement('netapp')
        netapp_elem.add_attr('xmlns', self._ns)
        if hasattr(self, '_api_version'):
            netapp_elem.add_attr('version', self._api_version)
        if enable_tunneling:
            self._enable_tunnel_request(netapp_elem)
        netapp_elem.add_child_elem(na_element)
        return netapp_elem

    def _enable_tunnel_request(self, netapp_elem):
        """Enables vserver or vfiler tunneling."""
        if hasattr(self, '_vfiler') and self._vfiler:
            if (hasattr(self, '_api_major_version') and
                    hasattr(self, '_api_minor_version') and
                    self._api_major_version >= 1 and
                    self._api_minor_version >= 7):
                netapp_elem.add_attr('vfiler', self._vfiler)
            else:
                raise ValueError('ontapi version has to be atleast 1.7'
                                 ' to send request to vfiler')
        if hasattr(self, '_vserver') and self._vserver:
            if (hasattr(self, '_api_major_version') and
                    hasattr(self, '_api_minor_version') and
                    self._api_major_version >= 1 and
                    self._api_minor_version >= 15):
                netapp_elem.add_attr('vfiler', self._vserver)
            else:
                raise ValueError('ontapi version has to be atleast 1.15'
                                 ' to send request to vserver')

    @staticmethod
    def _parse_response(response):
        """Get the NaElement for the response."""
        if not response:
            raise NaApiError('No response received')
        xml = etree.XML(response)
        return NaElement(xml)

    def _get_result(self, response):
        """Gets the call result."""
        processed_response = self._parse_response(response)
        return processed_response.get_child_by_name('results')

    def _get_url(self):
        """Get the base url to send the request."""
        host = self._host
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%s/%s' % (self._protocol, host, self._port, self._url)

    def _build_headers(self):
        """Build and return headers."""
        return {'Content-Type': 'text/xml'}


class RestClient(BaseClient):

    def __init__(self, host, transport_type=TRANSPORT_TYPE_HTTP,
                 style=STYLE_LOGIN_PASSWORD, ssl_cert_path=None, username=None,
                 password=None, port=None, trace=False,
                 api_trace_pattern=utils.API_TRACE_PATTERN):
        super(RestClient, self).__init__(
            host, transport_type=transport_type, style=style,
            ssl_cert_path=ssl_cert_path, username=username, password=password,
            port=port, trace=trace, api_trace_pattern=api_trace_pattern)
        if port is None:
            # Not yet set in parent, use defaults
            self._set_port()

    def _set_port(self):
        if self._protocol == TRANSPORT_TYPE_HTTP:
            self.set_port(80)
        else:
            self.set_port(443)

    def _get_request_info(self, api_name, session):
        """Returns the request method and url to be used in the REST call."""

        request_methods = {
            'post': session.post,
            'get': session.get,
            'put': session.put,
            'delete': session.delete,
            'patch': session.patch,
        }
        rest_call = rest_endpoints.endpoints.get(api_name)
        return request_methods[rest_call['method']], rest_call['url']

    def _add_query_params_to_url(self, url, query):
        """Populates the URL with specified filters."""
        filters = ""
        for k, v in query.items():
            filters += "%(key)s=%(value)s&" % {"key": k, "value": v}
        url += "?" + filters
        return url

    def invoke_elem(self, na_element, api_args=None):
        """Invoke the API on the server."""
        if na_element and not isinstance(na_element, NaElement):
            raise ValueError('NaElement must be supplied to invoke API')

        api_name = na_element.get_name()
        api_name_matches_regex = (re.match(self._api_trace_pattern, api_name)
                                  is not None)
        data = api_args.get("body") if api_args else {}

        if (not hasattr(self, '_session') or not self._session
                or self._refresh_conn):
            self._build_session()
        request_method, action_url = self._get_request_info(
            api_name, self._session)

        url_params = api_args.get("url_params") if api_args else None
        if url_params:
            action_url = action_url % url_params

        query = api_args.get("query") if api_args else None
        if query:
            action_url = self._add_query_params_to_url(
                action_url, api_args['query'])

        url = self._get_base_url() + action_url
        data = jsonutils.dumps(data) if data else data

        if self._trace and api_name_matches_regex:
            message = ("Request: %(method)s %(url)s. Request body "
                       "%(body)s") % {
                "method": request_method,
                "url": action_url,
                "body": api_args.get("body") if api_args else {}
            }
            LOG.debug(message)

        try:
            if hasattr(self, '_timeout'):
                response = request_method(
                    url, data=data, timeout=self._timeout)
            else:
                response = request_method(url, data=data)
        except requests.HTTPError as e:
            raise NaApiError(e.errno, e.strerror)
        except requests.URLRequired as e:
            raise exception.StorageCommunicationException(str(e))
        except Exception as e:
            raise NaApiError(message=e)

        response = (
            jsonutils.loads(response.content) if response.content else None)
        if self._trace and api_name_matches_regex:
            LOG.debug("Response: %s", response)

        return response

    def invoke_successfully(self, na_element, api_args=None,
                            enable_tunneling=False, use_zapi=False):
        """Invokes API and checks execution status as success.

        Need to set enable_tunneling to True explicitly to achieve it.
        This helps to use same connection instance to enable or disable
        tunneling. The vserver or vfiler should be set before this call
        otherwise tunneling remains disabled.
        """
        result = self.invoke_elem(na_element, api_args=api_args)
        if not result.get('error'):
            return result
        result_error = result.get('error')
        code = (result_error.get('code')
                or 'ESTATUSFAILED')
        if code == ESIS_CLONE_NOT_LICENSED:
            msg = 'Clone operation failed: FlexClone not licensed.'
        else:
            msg = (result_error.get('message')
                   or 'Execution status is failed due to unknown reason')
        raise NaApiError(code, msg)

    def _get_base_url(self):
        """Get the base URL for REST requests."""
        host = self._host
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%s/api/' % (self._protocol, host, self._port)

    def _build_headers(self):
        """Build and return headers for a REST request."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        return headers


class NaServer(object):
    """Encapsulates server connection logic."""

    def __init__(self, host, transport_type=TRANSPORT_TYPE_HTTP,
                 style=STYLE_LOGIN_PASSWORD, ssl_cert_path=None, username=None,
                 password=None, port=None, trace=False,
                 api_trace_pattern=utils.API_TRACE_PATTERN):
        self.zapi_client = ZapiClient(
            host, transport_type=transport_type, style=style,
            ssl_cert_path=ssl_cert_path, username=username, password=password,
            port=port, trace=trace, api_trace_pattern=api_trace_pattern)
        self.rest_client = RestClient(
            host, transport_type=transport_type, style=style,
            ssl_cert_path=ssl_cert_path, username=username, password=password,
            port=port, trace=trace, api_trace_pattern=api_trace_pattern
        )
        self._host = host

        LOG.debug('Using NetApp controller: %s', self._host)

    def get_transport_type(self, use_zapi_client=True):
        """Get the transport type protocol."""
        return self.get_client(use_zapi=use_zapi_client).get_transport_type()

    def set_transport_type(self, transport_type):
        """Set the transport type protocol for API.

        Supports http and https transport types.
        """
        self.zapi_client.set_transport_type(transport_type)
        self.rest_client.set_transport_type(transport_type)

    def get_style(self, use_zapi_client=True):
        """Get the authorization style for communicating with the server."""
        return self.get_client(use_zapi=use_zapi_client).get_style()

    def set_style(self, style):
        """Set the authorization style for communicating with the server.

        Supports basic_auth for now. Certificate_auth mode to be done.
        """
        self.zapi_client.set_style(style)
        self.rest_client.set_style(style)

    def get_server_type(self, use_zapi_client=True):
        """Get the target server type."""
        return self.get_client(use_zapi=use_zapi_client).get_server_type()

    def set_server_type(self, server_type):
        """Set the target server type.

        Supports filer and dfm server types.
        """
        self.zapi_client.set_server_type(server_type)
        self.rest_client.set_server_type(server_type)

    def set_api_version(self, major, minor):
        """Set the API version."""
        self.zapi_client.set_api_version(major, minor)
        self.rest_client.set_api_version(1, 0)

    def set_system_version(self, system_version):
        """Set the ONTAP system version."""
        self.zapi_client.set_system_version(system_version)
        self.rest_client.set_system_version(system_version)

    def get_api_version(self, use_zapi_client=True):
        """Gets the API version tuple."""
        return self.get_client(use_zapi=use_zapi_client).get_api_version()

    def get_system_version(self, use_zapi_client=True):
        """Gets the ONTAP system version."""
        return self.get_client(use_zapi=use_zapi_client).get_system_version()

    def set_port(self, port):
        """Set the server communication port."""
        self.zapi_client.set_port(port)
        self.rest_client.set_port(port)

    def get_port(self, use_zapi_client=True):
        """Get the server communication port."""
        return self.get_client(use_zapi=use_zapi_client).get_port()

    def set_timeout(self, seconds):
        """Sets the timeout in seconds."""
        self.zapi_client.set_timeout(seconds)
        self.rest_client.set_timeout(seconds)

    def get_timeout(self, use_zapi_client=True):
        """Gets the timeout in seconds if set."""
        return self.get_client(use_zapi=use_zapi_client).get_timeout()

    def get_vfiler(self):
        """Get the vfiler to use in tunneling."""
        return self.zapi_client.get_vfiler()

    def set_vfiler(self, vfiler):
        """Set the vfiler to use if tunneling gets enabled."""
        self.zapi_client.set_vfiler(vfiler)

    def get_vserver(self, use_zapi_client=True):
        """Get the vserver to use in tunneling."""
        return self.get_client(use_zapi=use_zapi_client).get_vserver()

    def set_vserver(self, vserver):
        """Set the vserver to use if tunneling gets enabled."""
        self.zapi_client.set_vserver(vserver)
        self.rest_client.set_vserver(vserver)

    def set_username(self, username):
        """Set the user name for authentication."""
        self.zapi_client.set_username(username)
        self.rest_client.set_username(username)

    def set_password(self, password):
        """Set the password for authentication."""
        self.zapi_client.set_password(password)
        self.rest_client.set_password(password)

    def get_client(self, use_zapi=True):
        """Chooses the client to be used in the request."""
        if use_zapi:
            return self.zapi_client
        return self.rest_client

    def invoke_successfully(self, na_element, api_args=None,
                            enable_tunneling=False, use_zapi=True):
        """Invokes API and checks execution status as success.

        Need to set enable_tunneling to True explicitly to achieve it.
        This helps to use same connection instance to enable or disable
        tunneling. The vserver or vfiler should be set before this call
        otherwise tunneling remains disabled.
        """
        return self.get_client(use_zapi=use_zapi).invoke_successfully(
            na_element, api_args=api_args, enable_tunneling=enable_tunneling)

    def __str__(self):
        return "server: %s" % (self._host)


class NaElement(object):
    """Class wraps basic building block for NetApp API request."""

    def __init__(self, name):
        """Name of the element or etree.Element."""
        if isinstance(name, etree._Element):
            self._element = name
        else:
            self._element = etree.Element(name)

    def get_name(self):
        """Returns the tag name of the element."""
        return self._element.tag

    def set_content(self, text):
        """Set the text string for the element."""
        self._element.text = text

    def get_content(self):
        """Get the text for the element."""
        return self._element.text

    def add_attr(self, name, value):
        """Add the attribute to the element."""
        self._element.set(name, value)

    def add_attrs(self, **attrs):
        """Add multiple attributes to the element."""
        for attr in attrs.keys():
            self._element.set(attr, attrs.get(attr))

    def add_child_elem(self, na_element):
        """Add the child element to the element."""
        if isinstance(na_element, NaElement):
            self._element.append(na_element._element)
            return
        raise ValueError(_("Can only add elements of type NaElement."))

    def get_child_by_name(self, name):
        """Get the child element by the tag name."""
        for child in self._element.iterchildren():
            if child.tag == name or etree.QName(child.tag).localname == name:
                return NaElement(child)
        return None

    def get_child_content(self, name):
        """Get the content of the child."""
        for child in self._element.iterchildren():
            if child.tag == name or etree.QName(child.tag).localname == name:
                return child.text
        return None

    def get_children(self):
        """Get the children for the element."""
        return [NaElement(el) for el in self._element.iterchildren()]

    def has_attr(self, name):
        """Checks whether element has attribute."""
        attributes = self._element.attrib or {}
        return name in attributes.keys()

    def get_attr(self, name):
        """Get the attribute with the given name."""
        attributes = self._element.attrib or {}
        return attributes.get(name)

    def get_attr_names(self):
        """Returns the list of attribute names."""
        attributes = self._element.attrib or {}
        return attributes.keys()

    def add_new_child(self, name, content, convert=False):
        """Add child with tag name and context.

           Convert replaces entity refs to chars.
        """
        child = NaElement(name)
        if convert:
            content = NaElement._convert_entity_refs(content)
        child.set_content(content)
        self.add_child_elem(child)

    @staticmethod
    def _convert_entity_refs(text):
        """Converts entity refs to chars to handle etree auto conversions."""
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        return text

    @staticmethod
    def create_node_with_children(node, **children):
        """Creates and returns named node with children."""
        parent = NaElement(node)
        for child in children.keys():
            parent.add_new_child(child, children.get(child, None))
        return parent

    def add_node_with_children(self, node, **children):
        """Creates named node with children."""
        parent = NaElement.create_node_with_children(node, **children)
        self.add_child_elem(parent)

    def to_string(self, pretty=False, method='xml', encoding='UTF-8'):
        """Prints the element to string."""
        return etree.tostring(self._element, method=method, encoding=encoding,
                              pretty_print=pretty)

    def __getitem__(self, key):
        """Dict getter method for NaElement.

            Returns NaElement list if present,
            text value in case no NaElement node
            children or attribute value if present.
        """

        child = self.get_child_by_name(key)
        if child:
            if child.get_children():
                return child
            else:
                return child.get_content()
        elif self.has_attr(key):
            return self.get_attr(key)
        raise KeyError(_('No element by given name %s.') % (key))

    def __setitem__(self, key, value):
        """Dict setter method for NaElement.

           Accepts dict, list, tuple, str, int, float and long as valid value.
        """
        if key:
            if value:
                if isinstance(value, NaElement):
                    child = NaElement(key)
                    child.add_child_elem(value)
                    self.add_child_elem(child)
                elif isinstance(
                        value,
                        (str, ) + (int, ) + (float, )):
                    self.add_new_child(key, str(value))
                elif isinstance(value, (list, tuple, dict)):
                    child = NaElement(key)
                    child.translate_struct(value)
                    self.add_child_elem(child)
                else:
                    raise TypeError(_('Not a valid value for NaElement.'))
            else:
                self.add_child_elem(NaElement(key))
        else:
            raise KeyError(_('NaElement name cannot be null.'))

    def translate_struct(self, data_struct):
        """Convert list, tuple, dict to NaElement and appends.

           Example usage:
           1.
           <root>
               <elem1>vl1</elem1>
               <elem2>vl2</elem2>
               <elem3>vl3</elem3>
           </root>
           The above can be achieved by doing
           root = NaElement('root')
           root.translate_struct({'elem1': 'vl1', 'elem2': 'vl2',
                                  'elem3': 'vl3'})
           2.
           <root>
               <elem1>vl1</elem1>
               <elem2>vl2</elem2>
               <elem1>vl3</elem1>
           </root>
           The above can be achieved by doing
           root = NaElement('root')
           root.translate_struct([{'elem1': 'vl1', 'elem2': 'vl2'},
                                  {'elem1': 'vl3'}])
        """
        if isinstance(data_struct, (list, tuple)):
            for el in data_struct:
                if isinstance(el, (list, tuple, dict)):
                    self.translate_struct(el)
                else:
                    self.add_child_elem(NaElement(el))
        elif isinstance(data_struct, dict):
            for k in data_struct.keys():
                child = NaElement(k)
                if isinstance(data_struct[k], (dict, list, tuple)):
                    child.translate_struct(data_struct[k])
                else:
                    if data_struct[k]:
                        child.set_content(str(data_struct[k]))
                self.add_child_elem(child)
        else:
            raise ValueError(_('Type cannot be converted into NaElement.'))


class NaApiError(Exception):
    """Base exception class for NetApp API errors."""

    def __init__(self, code='unknown', message='unknown'):
        self.code = code
        self.message = message

    def __str__(self, *args, **kwargs):
        return 'NetApp API failed. Reason - %s:%s' % (self.code, self.message)


def invoke_api(na_server, api_name, api_family='cm', query=None,
               des_result=None, additional_elems=None,
               is_iter=False, records=0, tag=None,
               timeout=0, tunnel=None):
    """Invokes any given API call to a NetApp server.

        :param na_server: na_server instance
        :param api_name: API name string
        :param api_family: cm or 7m
        :param query: API query as dict
        :param des_result: desired result as dict
        :param additional_elems: dict other than query and des_result
        :param is_iter: is iterator API
        :param records: limit for records, 0 for infinite
        :param timeout: timeout seconds
        :param tunnel: tunnel entity, vserver or vfiler name
    """
    record_step = 50
    if not (na_server or isinstance(na_server, NaServer)):
        msg = _("Requires an NaServer instance.")
        raise exception.InvalidInput(reason=msg)
    server = copy.copy(na_server)
    if api_family == 'cm':
        server.set_vserver(tunnel)
    else:
        server.set_vfiler(tunnel)
    if timeout > 0:
        server.set_timeout(timeout)
    iter_records = 0
    cond = True
    while cond:
        na_element = create_api_request(
            api_name, query, des_result, additional_elems,
            is_iter, record_step, tag)
        result = server.invoke_successfully(na_element, True)
        if is_iter:
            if records > 0:
                iter_records = iter_records + record_step
                if iter_records >= records:
                    cond = False
            tag_el = result.get_child_by_name('next-tag')
            tag = tag_el.get_content() if tag_el else None
            if not tag:
                cond = False
        else:
            cond = False
        yield result


def create_api_request(api_name, query=None, des_result=None,
                       additional_elems=None, is_iter=False,
                       record_step=50, tag=None):
    """Creates a NetApp API request.

        :param api_name: API name string
        :param query: API query as dict
        :param des_result: desired result as dict
        :param additional_elems: dict other than query and des_result
        :param is_iter: is iterator API
        :param record_step: records at a time for iter API
        :param tag: next tag for iter API
    """
    api_el = NaElement(api_name)
    if query:
        query_el = NaElement('query')
        query_el.translate_struct(query)
        api_el.add_child_elem(query_el)
    if des_result:
        res_el = NaElement('desired-attributes')
        res_el.translate_struct(des_result)
        api_el.add_child_elem(res_el)
    if additional_elems:
        api_el.translate_struct(additional_elems)
    if is_iter:
        api_el.add_new_child('max-records', str(record_step))
    if tag:
        api_el.add_new_child('tag', tag, True)
    return api_el
