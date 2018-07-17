.. -*- rst -*-

============================================
Share access rule metadata (Since API v2.45)
============================================

Updates, and unsets share access rule metadata.

Update share access rule metadata
==================================

.. rest_method::  PUT /v2/{tenant_id}/share-access-rules/{access_id}/metadata

Updates the metadata for a share access rule.

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

   - metadata: access_metadata
   - access_id: access_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-access-rules-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: access_metadata

Response example
----------------

.. literalinclude:: samples/share-access-rules-update-metadata-response.json
   :language: javascript


Unset share access rule metadata
================================

.. rest_method::  DELETE /v2/{tenant_id}/share-access-rules/{access_id}/metadata/{key}

Un-sets the metadata on a share access rule.

To unset a metadata key value, specify only the key name in the
URI.

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

   - access_id: access_id_path
   - tenant_id: tenant_id_path
   - key: metadata_key_path
