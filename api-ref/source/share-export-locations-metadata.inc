.. -*- rst -*-

Export Location metadata (Since API v2.87)
==========================================

Shows, sets, updates, and unsets export location metadata.


Show all export location metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}/export_locations/{export_location_id}/metadata

.. versionadded:: 2.87

Shows all the metadata for a export location, as key and value pairs.

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
   - share_id: share_id
   - export_location_id: export_location_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/export-location-show-metadata-response.json
   :language: javascript


Show export location metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}/export_locations/{export_location_id}/metadata/{key}

.. versionadded:: 2.87

Retrieves a specific metadata item from a export location's metadata by its key. If
the specified key does not represent a valid metadata item, the API will
respond with HTTP 404.

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
   - share_id: share_id
   - export_location_id: export_location_id_path
   - key: metadata_key_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_item

Response example
----------------

.. literalinclude:: samples/export-location-show-metadata-item-response.json
   :language: javascript


Set export location metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/export_locations/{export_location_id}/metadata

.. versionadded:: 2.87

Allows adding new metadata items as key-value pairs. This API will not delete
pre-existing metadata items. If the request object contains metadata items
that already exist, they will be updated with new values as specified in the
request object.

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
   - share_id: share_id
   - export_location_id: export_location_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/export-location-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/export-location-set-metadata-response.json
   :language: javascript


Update export location metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/shares/{share_id}/export_locations/{export_location_id}/metadata

.. versionadded:: 2.87

Replaces the metadata for a given export location with the metadata (specified
as key-value pairs) in the request object. All pre-existing metadata of the
export location will be deleted and replaced with the new metadata supplied.

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
   - share_id: share_id
   - export_location_id: export_location_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/export-location-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/export-location-update-metadata-response.json
   :language: javascript


To delete all existing metadata items on a given export location, the request object
needs to specify an empty metadata object:

Request example
---------------

.. literalinclude:: samples/export-location-update-null-metadata-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/export-location-update-null-metadata-response.json
   :language: javascript


Delete export location metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/shares/{share_id}/export_locations/{export_location_id}/metadata/{key}

.. versionadded:: 2.87

Deletes a single metadata item on a export location, identified by its key. If
the specified key does not represent a valid metadata item, the API will
respond with HTTP 404.

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
   - share_id: share_id
   - export_location_id: export_location_id_path
   - key: metadata_key_path
