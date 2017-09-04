.. -*- rst -*-

================================
Share instances (since API v2.3)
================================

Administrators can list, show information for, explicitly set the
state of, and force-delete share instances. Use the ``policy.json``
file to grant permissions for these actions to other roles.


List share instances
====================

.. rest_method::  GET /v2/{tenant_id}/share_instances

Lists all share instances.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - export_location_id: export_location_id_query
   - export_location_path: export_location_path_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_5
   - access_rules_status: access_rules_status
   - share_id: share_id_2
   - availability_zone: availability_zone_1
   - created_at: created_at_5
   - replica_state: replica_state
   - export_location: export_location
   - export_locations: export_locations
   - share_network_id: share_network_id_4
   - share_server_id: share_server_id
   - host: host_6
   - id: id_13

Response example
----------------

.. literalinclude:: samples/share-instances-list-response.json
   :language: javascript


Show share instance details
===========================

.. rest_method::  GET /v2/{tenant_id}/share_instances/{share_instance_id}

Shows details for a share instance.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_instance_id: share_instance_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: status_5
   - access_rules_status: access_rules_status
   - share_id: share_id_2
   - availability_zone: availability_zone_1
   - created_at: created_at_5
   - replica_state: replica_state
   - export_location: export_location
   - export_locations: export_locations
   - share_network_id: share_network_id_4
   - share_server_id: share_server_id
   - host: host_6
   - id: id_13

Response example
----------------

.. literalinclude:: samples/share-show-instance-response.json
   :language: javascript


Reset share instance state
==========================

.. rest_method::  POST /v2/{tenant_id}/share_instances/{share_instance_id}/action

Administrator only. Explicitly updates the state of a share instance.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_instance_id: share_instance_id
   - status: status_5

Request example
---------------

.. literalinclude:: samples/share-instance-actions-reset-state-request.json
   :language: javascript


Force-delete share instance
===========================

.. rest_method::  POST /v2/{tenant_id}/share_instances/{share_instance_id}/action

Administrator only. Force-deletes a share instance.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_instance_id: share_instance_id
   - force_delete: force_delete_2

Request example
---------------

.. literalinclude:: samples/share-instance-actions-force-delete-request.json
   :language: javascript
