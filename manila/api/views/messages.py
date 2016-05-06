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


from manila.api import common
from manila.message import message_field


class ViewBuilder(common.ViewBuilder):
    """Model a server API response as a python dictionary."""

    _collection_name = "messages"

    def index(self, request, messages):
        """Show a list of messages."""
        return self._list_view(self.detail, request, messages)

    def detail(self, request, message):
        """Detailed view of a single message."""
        message_ref = {
            'id': message.get('id'),
            'project_id': message.get('project_id'),
            'action_id': message.get('action_id'),
            'detail_id': message.get('detail_id'),
            'message_level': message.get('message_level'),
            'created_at': message.get('created_at'),
            'expires_at': message.get('expires_at'),
            'request_id': message.get('request_id'),
            'links': self._get_links(request, message['id']),
            'resource_type': message.get('resource_type'),
            'resource_id': message.get('resource_id'),
            'user_message': "%s: %s" % (
                message_field.translate_action(message.get('action_id')),
                message_field.translate_detail(message.get('detail_id'))),
        }

        return {'message': message_ref}

    def _list_view(self, func, request, messages, coll_name=_collection_name):
        """Provide a view for a list of messages.

        :param func: Function used to format the message data
        :param request: API request
        :param messages: List of messages in dictionary format
        :param coll_name: Name of collection, used to generate the next link
                          for a pagination query
        :returns: message data in dictionary format
        """
        messages_list = [func(request, message)['message']
                         for message in messages]
        messages_links = self._get_collection_links(request,
                                                    messages,
                                                    coll_name)
        messages_dict = dict({"messages": messages_list})

        if messages_links:
            messages_dict['messages_links'] = messages_links

        return messages_dict
