.. -*- rst -*-

Share instances (since API v2.3)
================================

A share instance is an internal representation for a share. A share that is
replicated or is in the process of being migrated is physically stored in
multiple locations. Each of these individual locations is called an "instance"
within the Shared File Systems service. End users need not be concerned with
this internal representation. As an administrator, you can list, show
information for, explicitly set the state of, and force-delete share instances.
Use the ``policy.yaml`` file to grant permissions for these actions to other
roles.


List share instances
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share_instances

.. versionadded:: 2.3

Lists all share instances.

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
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: share_status_response
   - access_rules_status: access_rules_status
   - share_id: share_id_share_instances_response
   - progress: progress_share_instance
   - availability_zone: availability_zone
   - created_at: created_at
   - updated_at: updated_at
   - replica_state: replica_state
   - export_location: export_location
   - export_locations: export_locations
   - cast_rules_to_readonly: share_instance_cast_rules_to_readonly
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: host_resource_response
   - access_rules_status: access_rules_status
   - share_type_id: share_type_id
   - id: id_13

Response example
----------------

.. literalinclude:: samples/share-instances-list-response.json
   :language: javascript


Show share instance details
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share_instances/{share_instance_id}

.. versionadded:: 2.3

Shows details for a share instance.

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
   - share_instance_id: share_instance_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: share_status_response
   - access_rules_status: access_rules_status
   - share_id: share_id_share_instances_response
   - progress: progress_share_instance
   - availability_zone: availability_zone
   - created_at: created_at
   - updated_at: updated_at
   - replica_state: replica_state
   - export_location: export_location
   - export_locations: export_locations
   - cast_rules_to_readonly: share_instance_cast_rules_to_readonly
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: host_resource_response
   - id: id_13

Response example
----------------

.. literalinclude:: samples/share-show-instance-response.json
   :language: javascript


Reset share instance state
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share_instances/{share_instance_id}/action

.. versionadded:: 2.3

Administrator only. Explicitly updates the state of a share instance.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

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
   - share_instance_id: share_instance_id
   - status: share_status_request

Request example
---------------

.. literalinclude:: samples/share-instance-actions-reset-state-request.json
   :language: javascript


Force-delete share instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share_instances/{share_instance_id}/action

.. versionadded:: 2.3

Administrator only. Force-deletes a share instance.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

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
   - share_instance_id: share_instance_id
   - force_delete: force_delete_2

Request example
---------------

.. literalinclude:: samples/share-instance-actions-force-delete-request.json
   :language: javascript
