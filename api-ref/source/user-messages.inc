.. -*- rst -*-

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
~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/messages

.. versionadded:: 2.37

Lists all user messages.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
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
   - created_since: created_since
   - created_before: created_before

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: message_id_body
   - action_id: action_id_body
   - detail_id: detail_id_body
   - message_level: message_level_body
   - project_id: project_id_messages_body
   - request_id: request_id_body
   - resource_id: resource_id_body
   - resource_type: resource_type_body
   - message_members_links: message_members_links
   - expires_at : message_expires_at_body
   - created_at : created_at


Response example
----------------

.. literalinclude:: samples/user-messages-list-response.json
   :language: javascript


Show user message details
~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/messages/{message_id}

.. versionadded:: 2.37

Shows details for a user message.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - message_id: message_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: message_id_body
   - action_id: action_id_body
   - detail_id: detail_id_body
   - message_level: message_level_body
   - project_id: project_id_messages_body
   - request_id: request_id_body
   - resource_id: resource_id_body
   - resource_type: resource_type_body
   - message_links: message_links
   - expires_at : message_expires_at_body
   - created_at : created_at


Response example
----------------

.. literalinclude:: samples/user-message-show-response.json
   :language: javascript


Delete message
~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/messages/{message_id}

.. versionadded:: 2.37

Deletes a user message.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - message_id: message_id
