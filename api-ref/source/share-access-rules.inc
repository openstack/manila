.. -*- rst -*-

.. _get-access-rules-after-2-45:

Share access rules (since API v2.45)
====================================

Retrieve details about access rules

.. note::
  Starting from API version 2.82, access rule visibility can be restricted
  by a project user, or any user with "service" or "admin" roles. When
  restricted, the access_to and access_key fields will be redacted to other
  users. This redaction applies irrespective of the API version.

Describe share access rule
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-access-rules/{access_id}

.. versionadded:: 2.45

Retrieve details about a specified access rule.

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
   - access_id: access_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: access_share_id
   - created_at: created_at
   - updated_at: updated_at
   - access_type: access_type
   - access_to: access_to
   - access_key: access_key_share_access_rules
   - state: state
   - access_level: access_level
   - id: access_rule_id
   - metadata: access_metadata

Response example
----------------

.. literalinclude:: samples/share-access-rules-show-response.json
   :language: javascript


List share access rules
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-access-rules?share_id={share-id}

.. versionadded:: 2.45

Lists the share access rules on a share.

.. note::
  This API replaces the older :ref:`List share access rules
  <get-access-rules-before-2-45>` API from version 2.45.

.. note::
  Starting from API version 2.82, access rule visibility can be restricted
  by a project user, or any user with "service" or "admin" roles. When
  restricted, the access_to and access_key fields will be redacted to other
  users. This redaction applies irrespective of the API version.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id_access_rules_query
   - metadata: metadata

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: access_metadata
   - access_type: access_type
   - access_key: access_key_share_access_rules
   - access_to: access_to
   - access_level: access_level
   - state: state
   - access_list: access_list
   - id: access_rule_id
   - created_at: created_at
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/share-access-rules-list-response.json
   :language: javascript
