.. -*- rst -*-

Share network subnets metadata (since API v2.78)
================================================

Shows, sets, updates, and unsets share network subnets metadata.


Show all share network subnets metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}/metadata

Shows all share network subnet metadata in the given share network subnet.

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
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-network-subnet-show-metadata-response.json
   :language: javascript


Show share network subnet metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}/metadata/{key}

Retrieves a specific metadata item from a share network subnet's metadata by its key. If
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
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path
   - key: metadata_key_request

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - meta: metadata_item

Response example
----------------

.. literalinclude:: samples/share-show-network-subnet-metadata-item-response.json
   :language: javascript


Set share network subnet metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}/metadata

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-network-subnet-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-network-subnet-set-metadata-response.json
   :language: javascript


Update share network subnet metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}/metadata

Replaces the metadata for a given share network subnet with the metadata (specified as
key-value pairs) in the request object. All pre-existing metadata of the
share network subnet will be deleted and replaced with the new metadata supplied.

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
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-network-subnet-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-network-subnet-update-metadata-response.json
   :language: javascript


To delete all existing metadata items on a given share network subnet,
the request object needs to specify an empty metadata object:

Request example
---------------

.. literalinclude:: samples/share-network-subnet-update-null-metadata-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-network-subnet-update-null-metadata-response.json
   :language: javascript


Delete share network subnet metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}/metadata/{key}

Deletes a single metadata item on a share network subnet, identified by its key. If
the specified key does not represent a valid metadata item, the API will
respond with HTTP 404.

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
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path
   - key: metadata_key_request
