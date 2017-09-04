.. -*- rst -*-

==============
Share metadata
==============

Shows, sets, updates, and unsets share metadata.


Show share metadata
===================

.. rest_method::  GET /v2/{tenant_id}/shares/{share_id}/metadata

Shows the metadata for a share.

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

   - metadata: metadata_3

Response example
----------------

.. literalinclude:: samples/share-show-metadata-response.json
   :language: javascript


Set share metadata
==================

.. rest_method::  POST /v2/{tenant_id}/shares/{share_id}/metadata

Sets the metadata on a share.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_2
   - share_id: share_id
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-set-metadata-response.json
   :language: javascript


Update share metadata
=====================

.. rest_method::  PUT /v2/{tenant_id}/shares/{share_id}/metadata

Updates the metadata for a share.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_2
   - share_id: share_id
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_3

Response example
----------------

.. literalinclude:: samples/share-update-metadata-response.json
   :language: javascript


Unset share metadata
====================

.. rest_method::  DELETE /v2/{tenant_id}/shares/{share_id}/metadata/{key}

Un-sets the metadata on a share.

To unset a metadata key value, specify only the key name in the
URI.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path
   - key: metadata_key_request
