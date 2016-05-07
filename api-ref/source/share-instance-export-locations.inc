.. -*- rst -*-

================================================
Share instance export locations (since API v2.9)
================================================

Set of APIs used to view export locations of share instances.

By default, these APIs are admin-only. Use the ``policy.json`` file
to grant permissions for these actions to other roles.

Lists all export locations for a share instance.

Show details of an export location belonging to a share instance.


List export locations
=====================

.. rest_method::  GET /v2/{tenant_id}/share_instances/{share_instance_id}/export_locations

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - share_instance_id: share_instance_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_5
   - share_instance_id: share_instance_id_1
   - path: path
   - is_admin_only: is_admin_only
   - preferred: preferred

Response example
----------------

.. literalinclude:: samples/export-location-list-response.json
   :language: javascript


Show single export location
===========================

.. rest_method::  GET /v2/{tenant_id}/share_instances/{share_instance_id}/export_locations/{export_location_id}


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - share_instance_id: share_instance_id
   - export_location_id: export_location_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_5
   - share_instance_id: share_instance_id_1
   - path: path
   - is_admin_only: is_admin_only
   - preferred: preferred
   - created_at: created_at_5
   - updated_at: updated_at_2

Response example
----------------

.. literalinclude:: samples/export-location-show-response.json
   :language: javascript
