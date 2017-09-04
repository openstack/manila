.. -*- rst -*-

==============================
User messages (since API 2.37)
==============================

Lists, shows and deletes user messages.

User messages are automatically created when an asynchronous action fails on a
resource. In such situations an error is logged in the appropriate log file but
end users may not have access to the log files. User messages can be used by
users to get error details for failed actions. This is handy for example when
creating shares - if a share creation fails because a scheduling filter doesn't
find suitable back-end host for the share, this share will end up in error
state, but from user messages API users can get details about the last
executed filter which helps them identify the issue and perhaps re-attempt the
creation request with different parameters.


List user messages
==================

.. rest_method::  GET /v2/{tenant_id}/messages

Lists all user messages.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
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

   - tenant_id: tenant_id_path
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

   - tenant_id: tenant_id_path
   - message_id: message_id
