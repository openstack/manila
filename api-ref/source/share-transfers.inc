.. -*- rst -*-

Share transfer (since API v2.77)
================================

Transfers a share across projects.


Create a share transfer
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-transfers

Initiates a share transfer from a source project namespace to a destination
project namespace.

**Preconditions**

* The share ``status`` must be ``available``
* If the share has snapshots, those snapshots must be ``available``
* The share can not belong to share  group

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 403
   - 404


Request
-------

.. rest_parameters:: parameters.yaml

   - transfer: transfer
   - name: transfer_name
   - share_id: share_id_request

Request Example
---------------

.. literalinclude:: ./samples/share-transfer-create-request.json
   :language: javascript


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: transfer_id_in_body
   - created_at: created_at
   - name: transfer_name
   - resource_type: transfer_resource_type
   - resource_id: transfer_resource_id
   - auth_key: auth_key
   - source_project_id: project_id
   - destination_project_id: destination_project_id
   - accepted: accepted
   - expires_at: transfer_expires_at_body
   - links: links


Response Example
----------------

.. literalinclude:: ./samples/share-transfer-create-response.json
   :language: javascript


Accept a share transfer in the destination project namespace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-transfers/{transfer_id}/accept

Accepts a share transfer.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 403
   - 404
   - 413

Request
-------

.. rest_parameters:: parameters.yaml

   - transfer_id: transfer_id
   - auth_key: auth_key
   - clear_access_rules: clear_access_rules

Request Example
---------------

.. literalinclude:: ./samples/share-transfer-accept-request.json
   :language: javascript


List share transfers for a project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-transfers

Lists share transfers.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200


Request
-------

.. rest_parameters:: parameters.yaml

   - all_tenants: all_tenants_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key_transfer
   - sort_dir: sort_dir
   - name: name_query
   - name~: name_inexact_query
   - resource_type: resource_type_query


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - transfers: transfers
   - id: transfer_id_in_body
   - resource_type: transfer_resource_type
   - resource_id: transfer_resource_id
   - name: transfer_name
   - links: links


Response Example
----------------

.. literalinclude:: ./samples/share-transfers-list-response.json
   :language: javascript


List share transfers and details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-transfers/detail

Lists share transfers, with details.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

Request
-------

.. rest_parameters:: parameters.yaml

   - all_tenants: all_tenants_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key_transfer
   - sort_dir: sort_dir

Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - transfers: transfers
   - id: transfer_id_in_body
   - created_at: created_at
   - name: transfer_name
   - resource_type: transfer_resource_type
   - resource_id: transfer_resource_id
   - source_project_id: project_id
   - destination_project_id: destination_project_id
   - accepted: accepted
   - expires_at: transfer_expires_at_body
   - links: links

Response Example
----------------

.. literalinclude:: ./samples/share-transfers-list-detailed-response.json
   :language: javascript


Show share transfer detail
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-transfers/{transfer_id}

Shows details for a share transfer.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 404


Request
-------

.. rest_parameters:: parameters.yaml

   - transfer_id: transfer_id


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: transfer_id_in_body
   - created_at: created_at
   - name: transfer_name
   - resource_type: transfer_resource_type
   - resource_id: transfer_resource_id
   - source_project_id: project_id
   - destination_project_id: destination_project_id
   - accepted: accepted
   - expires_at: transfer_expires_at_body
   - links: links


Response Example
----------------

.. literalinclude:: ./samples/share-transfer-show-response.json
   :language: javascript


Delete a share transfer
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-transfers/{transfer_id}

Deletes a share transfer.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202


Request
-------

.. rest_parameters:: parameters.yaml

   - transfer_id: transfer_id

