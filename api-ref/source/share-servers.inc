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

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_14
   - project_id: project_id_7
   - status: status_15
   - share_network_id: share_network_id
   - share_network_name: share_network_name
   - host: host_8
   - updated_at: updated_at_6

Response example
----------------

.. literalinclude:: samples/share-servers-list-response.json
   :language: javascript


Show share server details
=========================

.. rest_method::  GET /v2/{tenant_id}/share-servers/{share_server_id}/detail

Shows details for a share server.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_server_id: share_server_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: id_14
   - project_id: project_id_7
   - status: status_15
   - backend_details: backend_details
   - share_network_id: share_network_id_6
   - share_network_name: share_network_name
   - host: host_8
   - created_at: created_at_11
   - updated_at: updated_at_6

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

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_server_id: share_server_id
