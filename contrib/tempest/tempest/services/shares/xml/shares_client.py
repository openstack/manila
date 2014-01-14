# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

import collections

from lxml import etree

from tempest.common.utils.data_utils import rand_name
from tempest.services.compute.xml import common as xml
from tempest.services.shares.json import shares_client


class SharesClientXML(shares_client.SharesClientJSON):

    """
    Tempest REST client for Manila.
    It handles shares and access to it in openstack.
    """

    def __init__(self, config, username, password, auth_url, tenant_name=None):
        super(SharesClientXML, self).__init__(config, username, password,
                                              auth_url, tenant_name)
        self.TYPE = "xml"  # from RestClientXML
        self.headers["Content-Type"] = "application/%s" % self.TYPE
        self.headers["Accept"] = "application/%s" % self.TYPE

    def _parse_resp(self, body):  # from RestClientXML
        if len(body) > 0:
            element = etree.fromstring(body)
            entity_list = ["shares", "snapshots", "extensions", "access_list"]
            if "metadata" in element.tag:
                dictionary = {}
                for el in element.getchildren():
                    dictionary[u"%s" % el.get("key")] = u"%s" % el.text
                return dictionary
            elif any(s in element.tag for s in entity_list):
                s_list = []
                if element is not None:
                    s_list += [xml.xml_to_json(sh) for sh in list(element)]
                    return s_list
            else:
                return xml.xml_to_json(element)
        return body

    def is_absolute_limit(self, resp, resp_body):  # from RestClientXML
        if (not isinstance(resp_body, collections.Mapping) or
                'retry-after' not in resp):
            return True
        return 'exceed' in resp_body.get('message', 'blabla')

    def create_share(self, share_protocol=None,
                     size=1, name=None, snapshot_id=None,
                     description="tempest created share",
                     metadata={}):
        if name is None:
            name = rand_name("tempest-created-share-")
        if share_protocol is None:
            share_protocol = self.share_protocol

        share = xml.Element("share", xmlns=xml.XMLNS_11)
        share.append(xml.Element("share_proto", share_protocol))
        if description is not None:
            share.append(xml.Element("description", description))
        if snapshot_id is not None:
            share.append(xml.Element("snapshot_id", snapshot_id))
        share.append(xml.Element("name", name))
        share.append(xml.Element("size", size))

        metadata_el = xml.Element("metadata")
        for key, value in metadata.iteritems():
            metadata_el.append(xml.Element(key, value))
        share.append(metadata_el)

        resp, body = self.post('shares', str(xml.Document(share)),
                               self.headers)
        return resp, self._parse_resp(body)

    def create_access_rule(self, share_id, access_type="ip",
                           access_to="0.0.0.0"):
        rule = xml.Element("os-allow_access", xmlns=xml.XMLNS_11)
        rule.append(xml.Element("access_type", access_type))
        rule.append(xml.Element("access_to", access_to))

        uri = "shares/%s/action" % (share_id)
        resp, body = self.post(uri, str(xml.Document(rule)), self.headers)
        return resp, self._parse_resp(body)

    def list_access_rules(self, share_id):
        uri = "shares/%s/action" % (share_id)
        access_list = xml.Element("os-access_list",
                                  xmlns=xml.XMLNS_11,
                                  value=None)
        resp, body = self.post(uri, str(xml.Document(access_list)),
                               self.headers)
        return resp, self._parse_resp(body)

    def delete_access_rule(self, share_id, rule_id):
        rule = xml.Element("os-deny_access", xmlns=xml.XMLNS_11)
        rule.append(xml.Element("access_id", rule_id))
        uri = "shares/%s/action" % share_id
        return self.post(uri, str(xml.Document(rule)), self.headers)

    def create_snapshot(self, share_id, name=None,
                        description="tempest created share-ss", force=False):
        if name is None:
            name = rand_name("tempest-created-share-snap-")
        snap = xml.Element("snapshot", xmlns=xml.XMLNS_11)
        snap.append(xml.Element("name", name))
        snap.append(xml.Element("force", force))
        snap.append(xml.Element("description", description))
        snap.append(xml.Element("share_id", share_id))
        resp, body = self.post('snapshots', str(xml.Document(snap)),
                               self.headers)
        return resp, self._parse_resp(body)

    def update_quotas(self, tenant_id=None, user_id=None,
                      shares=None, snapshots=None, gigabytes=None,
                      force=True):
        uri = "os-quota-sets/%s" % tenant_id
        if user_id is not None:
            uri += "?user_id=%s" % user_id
        upd = xml.Element("quota_set", id=tenant_id)
        if force:
            upd.append(xml.Element("force", "true"))
        if shares is not None:
            upd.append(xml.Element("shares", shares))
        if snapshots is not None:
            upd.append(xml.Element("snapshots", snapshots))
        if gigabytes is not None:
            upd.append(xml.Element("gigabytes", gigabytes))
        resp, body = self.put(uri, str(xml.Document(upd)), self.headers)
        return resp, self._parse_resp(body)

    def get_limits(self):
        resp, element = self.get("limits", self.headers)
        element = etree.fromstring(element)
        limits = {"rate": [], "absolute": {}}

        for abs_el in element.getchildren():
            if "absolute" in abs_el.tag:
                element = abs_el
                break

        for child in element.getchildren():
            limit = {}
            for key, value in child.attrib.iteritems():
                limit[key] = value
            limits["absolute"][limit["name"]] = limit["value"]

        return resp, limits

    def rename(self, share_id, name, desc=None):
        uri = "shares/%s" % share_id
        share = xml.Element("share", xmlns=xml.XMLNS_11)
        share.append(xml.Element("display_name", name))
        if desc is not None:
            share.append(xml.Element("display_description", desc))
        resp, body = self.put(uri, str(xml.Document(share)), self.headers)
        return resp, self._parse_resp(body)

    def rename_snapshot(self, snapshot_id, name, desc=None):
        uri = "snapshots/%s" % snapshot_id
        snap = xml.Element("snapshot", xmlns=xml.XMLNS_11)
        snap.append(xml.Element("display_name", name))
        if desc is not None:
            snap.append(xml.Element("display_description", desc))
        resp, body = self.put(uri, str(xml.Document(snap)), self.headers)
        return resp, self._parse_resp(body)

    def reset_state(self, s_id, status="error", s_type="shares"):
        """
        Resets the state of a share or a snapshot
        status: available, error, creating, deleting, error_deleting
        s_type: shares, snapshots
        """
        uri = "%s/%s/action" % (s_type, s_id)
        body = xml.Element("os-reset_status", xmlns=xml.XMLNS_11)
        body.append(xml.Element("status", status))
        resp, body = self.post(uri, str(xml.Document(body)), self.headers)
        return resp, self._parse_resp(body)

    def _update_metadata(self, share_id, metadata={}, method="post"):
        uri = "shares/%s/metadata" % (str(share_id))
        metadata_el = xml.Element("metadata")
        for key, value in metadata.iteritems():
            metadata_el.append(xml.Element("meta", value, key=key))
        meta_str = str(xml.Document(metadata_el))
        if method is "post":
            resp, body = self.post(uri, meta_str, self.headers)
        elif method is "put":
            resp, body = self.put(uri, meta_str, self.headers)
        metas = self._parse_resp(body)
        return resp, metas
