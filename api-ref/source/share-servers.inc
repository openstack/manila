.. -*- rst -*-

=============
Share servers
=============

A share server is created by multi-tenant back-end drivers where
shares are hosted. For example, with the ``generic`` driver, shares
are hosted on Compute VMs.

Administrators can perform read and delete actions for share
servers. An administrator can delete an active share server only if
it contains no dependent shares. If an administrator deletes the
share server, the Shared File Systems service creates a share
server in response to a subsequent create share request.

An administrator can use the ``policy.json`` file to grant
permissions for share server actions to other roles.

The status of a share server indicates its current state. After you
successfully set up a share server, its status is ``active``. If
errors occur during set up such as when server data is not valid,
its status is ``error``.

The possible share servers statuses are:

**Share server statuses**

+--------------+------------------------------------------------------------------+
| Status       | Description                                                      |
+--------------+------------------------------------------------------------------+
| ``active``   | Share server was successfully set up.                            |
+--------------+------------------------------------------------------------------+
| ``error``    | The set up or deletion of the share server failed.               |
+--------------+------------------------------------------------------------------+
| ``deleting`` | The share server has no dependent shares and is being deleted.   |
+--------------+------------------------------------------------------------------+
| ``creating`` | The share server is being created on the back end with data from |
|              | the database.                                                    |
+--------------+------------------------------------------------------------------+


List share servers
==================

.. rest_method::  GET /v2/{tenant_id}/share-servers

Lists all share servers.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_server_id
   - project_id: project_id_share_server_body
   - status: status_share_server_body
   - share_network_id: share_network_id
   - share_network_name: share_network_name
   - host: host_share_server_body
   - updated_at: updated_at_share_server_body

Response example
----------------

.. literalinclude:: samples/share-servers-list-response.json
   :language: javascript


Show share server
=================

.. rest_method::  GET /v2/{tenant_id}/share-servers/{share_server_id}

Show a share server's details.

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

  - tenant_id: tenant_id_path
  - share_server_id: share_server_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

  - id: share_server_id
  - project_id: project_id_share_server_body
  - status: status_share_server_body
  - backend_details: backend_details
  - share_network_id: share_network_id_share_server_body
  - share_network_name: share_network_name
  - host: host_share_server_body
  - created_at: created_at_share_server_body
  - updated_at: updated_at_share_server_body

Response example
----------------

.. literalinclude:: samples/share-server-show-response.json
  :language: javascript


Show share server back end details
==================================

.. rest_method::  GET /v2/{tenant_id}/share-servers/{share_server_id}/details

Shows back end details of a share server.

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

   - tenant_id: tenant_id_path
   - share_server_id: share_server_id

Response parameters
-------------------

Response parameters can differ based on the back end used.
Each back end can store any key-value information that it requires.
For example, the generic back end driver might store the router ID.

Response example
----------------

.. literalinclude:: samples/share-server-show-details-response.json
   :language: javascript


Delete share server
===================

.. rest_method::  DELETE /v2/{tenant_id}/share-servers/{share_server_id}

Deletes a share server.

An administrator can delete an active share server only if it
contains no dependent shares.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_server_id: share_server_id
