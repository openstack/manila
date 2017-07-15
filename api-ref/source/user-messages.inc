.. -*- rst -*-

==============================
User messages (since API 2.37)
==============================

Lists, shows and deletes user messages.


List user messages
==================

.. rest_method::  GET /v2/{tenant_id}/messages

Lists all user messages.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - limit: limit
   - offset: offset
   - sort_key: sort_key_messages
   - sort_dir: sort_dir
   - action_id: action_id
   - detail_id: detail_id
   - message_level: message_level
   - project_id: project_id_messages
   - request_id: request_id
   - resource_id: resource_id
   - resource_type: resource_type

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - action_id: action_id_body
   - detail_id: detail_id_body
   - message_level: message_level_body
   - project_id: project_id_messages_body
   - request_id: request_id_body
   - resource_id: resource_id_body
   - resource_type: resource_type_body
   - message_members_links: message_members_links


Response example
----------------

.. literalinclude:: samples/user-messages-list-response.json
   :language: javascript


Show user message details
=========================

.. rest_method::  GET /v2/{tenant_id}/messages/{message_id}

Shows details for a user message.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - message_id: message_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - action_id: action_id_body
   - detail_id: detail_id_body
   - message_level: message_level_body
   - project_id: project_id_messages_body
   - request_id: request_id_body
   - resource_id: resource_id_body
   - resource_type: resource_type_body
   - message_links: message_links


Response example
----------------

.. literalinclude:: samples/user-message-show-response.json
   :language: javascript


Delete message
==============

.. rest_method::  DELETE /v2/{tenant_id}/messages/{message_id}

Deletes a user message.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - message_id: message_id
