.. -*- rst -*-

Share instance export locations (since API v2.9)
================================================

Set of APIs used to view export locations of share instances.

By default, these APIs are admin-only. Use the ``policy.yaml`` file
to grant permissions for these actions to other roles.

Lists all export locations for a share instance.

Show details of an export location belonging to a share instance.


List export locations
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share_instances/{share_instance_id}/export_locations

.. versionadded:: 2.9

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

   - id: export_location_id
   - share_instance_id: export_location_share_instance_id
   - path: export_location_path
   - is_admin_only: export_location_is_admin_only
   - preferred: export_location_preferred

Response example
----------------

.. literalinclude:: samples/export-location-list-response.json
   :language: javascript


Show single export location
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share_instances/{share_instance_id}/export_locations/{export_location_id}

.. versionadded:: 2.9

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
   - export_location_id: export_location_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: export_location_id
   - share_instance_id: export_location_share_instance_id
   - path: export_location_path
   - is_admin_only: export_location_is_admin_only
   - preferred: export_location_preferred
   - created_at: created_at
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/export-location-show-response.json
   :language: javascript
