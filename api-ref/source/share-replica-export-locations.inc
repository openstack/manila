.. -*- rst -*-

.. _share_replica_export_locations:

Share replica export locations (since API v2.47)
================================================

Set of APIs used to view export locations of share replicas.

List export locations
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/{share_replica_id}/export-locations

.. versionadded:: 2.47

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
   - share_replica_id: share_replica_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: export_location_id
   - share_instance_id: export_location_share_instance_id
   - path: export_location_path
   - is_admin_only: export_location_is_admin_only
   - preferred: export_location_preferred_replicas
   - availability_zone: export_location_availability_zone
   - replica_state: share_replica_replica_state

Response example
----------------

.. literalinclude:: samples/share-replica-export-location-list-response.json
   :language: javascript


Show single export location
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/{share_replica_id}/export-locations/{export-location-id}

.. versionadded:: 2.47


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
   - share_replica_id: share_replica_id_path
   - export_location_id: export_location_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: export_location_id
   - share_instance_id: export_location_share_instance_id
   - path: export_location_path
   - is_admin_only: export_location_is_admin_only
   - preferred: export_location_preferred_replicas
   - availability_zone: export_location_availability_zone
   - replica_state: share_replica_replica_state
   - created_at: created_at
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/share-replica-export-location-show-response.json
   :language: javascript
