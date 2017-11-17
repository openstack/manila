.. -*- rst -*-

=======================================
Share export locations (since API v2.9)
=======================================

Set of APIs used for viewing export locations of shares.

By default, these APIs are admin-only. Use the ``policy.json`` file
to grant permissions for these actions to other roles.


List export locations
=====================

.. rest_method::  GET /v2/{tenant_id}/shares/{share_id}/export_locations

Lists all export locations for a share.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path

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
===========================

.. rest_method::  GET /v2/{tenant_id}/shares/{share_id}/export_locations/​{export_location_id}​

Show details of an export location belonging to a share.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path
   - export_location_id: export_location_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: export_location_id
   - share_instance_id: export_location_share_instance_id
   - path: export_location_path
   - is_admin_only: export_location_is_admin_only
   - preferred: export_location_preferred
   - created_at: export_location_created_at
   - updated_at: export_location_updated_at

Response example
----------------

.. literalinclude:: samples/export-location-show-response.json
   :language: javascript
