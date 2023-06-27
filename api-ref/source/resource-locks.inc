.. -*- rst -*-

Resource Locks (since API v2.81)
================================

Create, list, update and delete locks on user actions on resources.


Create a resource lock
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/resource-locks

.. versionadded:: 2.81

Lock a specific action on a given resource.

Not all resources are supported, and not actions on supported resources can
be prevented with this mechanism. A lock can only be removed or manipulated
by the user that created it, or by a more privileged user. The cloud
administrator can use a ``policy.yaml`` file to tweak permissions on who
can manipulate and delete locks created by other users.

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

   - service_token: service_token_locks
   - resource_lock: resource_lock_object
   - resource_id: resource_lock_resource_id
   - resource_type: resource_lock_resource_type
   - resource_action: resource_lock_resource_action_create_optional
   - lock_reason: resource_lock_lock_reason_optional

Request Example
---------------

.. literalinclude:: ./samples/resource-lock-create-request.json
   :language: javascript


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - resource_lock: resource_lock_object
   - id: resource_lock_id
   - user_id: resource_lock_user_id
   - project_id: resource_lock_project_id
   - lock_context: resource_lock_lock_context
   - resource_type: resource_lock_resource_type
   - resource_id: resource_lock_resource_id
   - resource_action: resource_lock_resource_action
   - lock_reason: resource_lock_lock_reason
   - created_at: created_at
   - updated_at: updated_at
   - links: links

Response Example
----------------

.. literalinclude:: ./samples/resource-lock-create-response.json
   :language: javascript


List resource locks
~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/resource-locks

.. versionadded:: 2.81

Retrieve resource locks with filters

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404


Request
-------

.. rest_parameters:: parameters.yaml

   - service_token: service_token_locks
   - id: resource_lock_id_query
   - resource_id: resource_lock_resource_id_query
   - resource_action: resource_lock_resource_action_query
   - resource_type: resource_lock_resource_type_query
   - user_id: resource_lock_user_id_query
   - project_id: resource_lock_project_id_query
   - all_projects: resource_lock_all_projects_query
   - lock_context: resource_lock_lock_context_query
   - created_since: created_since_query
   - created_before: created_before_query
   - lock_reason: resource_lock_lock_reason_query
   - lock_reason~: resource_lock_lock_reason_inexact_query
   - sort_key: sort_key_resource_locks
   - sort_dir: sort_dir
   - offset: offset
   - with_count: with_count_query_without_min_version


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - resource_locks: resource_locks_object
   - id: resource_lock_id
   - user_id: resource_lock_user_id
   - project_id: resource_lock_project_id
   - lock_context: resource_lock_lock_context
   - resource_type: resource_lock_resource_type
   - resource_id: resource_lock_resource_id
   - resource_action: resource_lock_resource_action
   - lock_reason: resource_lock_lock_reason
   - created_at: created_at
   - updated_at: updated_at
   - links: links
   - count: count_without_min_version

Response Example
----------------

.. literalinclude:: ./samples/resource-lock-get-all-response.json
   :language: javascript


Get a resource lock
~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/resource-locks/{resource-lock-id}

.. versionadded:: 2.81

Retrieve a specific resource lock

By default, resource locks can be viewed by all users within a project that
owns the locks. The cloud administrator can use a ``policy.yaml`` file to tweak
this behavior.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404


Request
-------

.. rest_parameters:: parameters.yaml

   - service_token: service_token_locks
   - resource_id: resource_lock_id_path


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - resource_lock: resource_lock_object
   - id: resource_lock_id
   - user_id: resource_lock_user_id
   - project_id: resource_lock_project_id
   - lock_context: resource_lock_lock_context
   - resource_type: resource_lock_resource_type
   - resource_id: resource_lock_resource_id
   - resource_action: resource_lock_resource_action
   - lock_reason: resource_lock_lock_reason
   - created_at: created_at
   - updated_at: updated_at
   - links: links

Response Example
----------------

.. literalinclude:: ./samples/resource-lock-get-response.json
   :language: javascript


Update a resource lock
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/resource-locks/{resource-lock-id}

.. versionadded:: 2.81

Update a specific resource lock

By default, resource locks can be updated by the user that created the lock
unless the ``lock_context`` is set to ``admin`` or ``service``. A user with
``service`` role is required to manipulate locks that have a ``lock_context``
set to ``service``. Users with ``admin`` role can manipulate all locks.
Administrators can use ``policy.yaml`` to tweak this behavior.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404


Request
-------

.. rest_parameters:: parameters.yaml

   - service_token: service_token_locks
   - resource_id: resource_lock_id_path
   - resource_lock: resource_lock_object
   - resource_action: resource_lock_resource_action_optional
   - lock_reason: resource_lock_lock_reason_optional

Request Example
----------------

.. literalinclude:: ./samples/resource-lock-update-request.json
   :language: javascript

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - resource_lock: resource_lock_object
   - id: resource_lock_id
   - user_id: resource_lock_user_id
   - project_id: resource_lock_project_id
   - lock_context: resource_lock_lock_context
   - resource_type: resource_lock_resource_type
   - resource_id: resource_lock_resource_id
   - resource_action: resource_lock_resource_action
   - lock_reason: resource_lock_lock_reason
   - created_at: created_at
   - updated_at: updated_at
   - links: links

Response Example
----------------

.. literalinclude:: ./samples/resource-lock-update-response.json
   :language: javascript


Delete a resource lock
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/resource-locks/{resource-lock-id}

.. versionadded:: 2.81

Delete a specific resource lock

By default, resource locks can be deleted by the user that created the lock
unless the ``lock_context`` is set to ``admin`` or ``service``. A user with
``service`` role is required to delete locks that have a ``lock_context``
set to ``service``. Users with ``admin`` role can delete any lock.
Administrators can use ``policy.yaml`` to tweak this behavior.

This request provides no response body.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 204

.. rest_status_code:: error status.yaml

   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - service_token: service_token_locks
   - resource_id: resource_lock_id_path
