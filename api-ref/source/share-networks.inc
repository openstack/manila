.. -*- rst -*-

==============
Share networks
==============

A share network stores network information that share servers can
use where shares are hosted. You can associate a share with a
single share network. When you create a share, you can optionally
specify the ID of a share network through which instances can
access the share.

You can create, update, view, and delete a share network.

When you create a share network, you may optionally specify an associated
neutron network and subnetwork:

- Neutron network. Specify a network ID and subnet ID.


For more information about supported plug-ins for share networks,
see `Manila Network Plugins <https://docs.openstack.org/manila/latest/
admin/shared-file-systems-network-plugins.html>`_.

A share network has these attributes:

- The IP block in Classless Inter-Domain Routing (CIDR) notation
  from which to allocate the network.

- The IP version of the network.

- The network type, which is ``vlan``, ``vxlan``, ``gre``, or
  ``flat``.

- If the network uses segmentation, a segmentation identifier. For
  example, VLAN, VXLAN, and GRE networks use segmentation.


List share networks
===================

.. rest_method::  GET /v2/{tenant_id}/share-networks

Lists all share networks.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - name~: name_inexact_query
   - description~: description_inexact_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - name: share_network_name

Response example
----------------

.. literalinclude:: samples/share-networks-list-response.json
   :language: javascript


List share networks with details
================================

.. rest_method::  GET /v2/{tenant_id}/share-networks/detail

Lists all share networks with details.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - name~: name_inexact_query
   - description~: description_inexact_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-networks-list-detailed-response.json
   :language: javascript


Show share network details
==========================

.. rest_method::  GET /v2/{tenant_id}/share-networks/{share_network_id}

Shows details for a share network.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_network_id: share_network_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-network-show-response.json
   :language: javascript


Create share network
====================

.. rest_method::  POST /v2/{tenant_id}/share-networks

Creates a share network.


Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
entityTooLarge(413), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - neutron_net_id: neutron_net_id_request
   - neutron_subnet_id: neutron_subnet_id_request
   - name: share_network_name_request
   - description: share_network_description_request

Request example
---------------

.. literalinclude:: samples/share-network-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type_1
   - segmentation_id: segmentation_id_1
   - cidr: cidr_1
   - ip_version: ip_version_1
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-network-create-response.json
   :language: javascript


Add security service to share network
=====================================

.. rest_method::  POST /v2/{tenant_id}/share-networks/{share_network_id}/action

Adds a security service to a share network.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - share_network_id: share_network_id_path
   - security_service_id: security_service_id

Request example
---------------

.. literalinclude:: samples/share-network-add-security-service-request.json
   :language: javascript


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-network-add-security-service-response.json
   :language: javascript


Remove security service from share network
==========================================

.. rest_method::  POST /v2/{tenant_id}/share-networks/{share_network_id}/action

Removes a security service from a share network.


Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_network_id: share_network_id_path
   - security_service_id: share_network_security_service_id

Request example
---------------

.. literalinclude:: samples/share-network-remove-security-service-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-network-remove-security-service-response.json
   :language: javascript


Update share network
====================

.. rest_method::  PUT /v2/{tenant_id}/share-networks/{share_network_id}

Updates a share network.

Note that if the share network is used by any share server, you can
update only the ``name`` and ``description`` attributes.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_network_id: share_network_id_path
   - name: share_network_name_request
   - description: share_network_description_request
   - neutron_net_id: neutron_net_id_request
   - neutron_subnet_id: neutron_subnet_id_request

Request example
---------------

.. literalinclude:: samples/share-network-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_id
   - project_id: project_id
   - neutron_net_id: neutron_net_id
   - neutron_subnet_id: neutron_subnet_id
   - network_type: network_type
   - segmentation_id: segmentation_id
   - cidr: cidr
   - ip_version: ip_version
   - name: share_network_name
   - description: share_network_description
   - created_at: share_network_created_at
   - updated_at: share_network_updated_at

Response example
----------------

.. literalinclude:: samples/share-network-update-response.json
   :language: javascript


Delete share network
====================

.. rest_method::  DELETE /v2/{tenant_id}/share-networks/{share_network_id}

Deletes a share network.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_network_id: share_network_id_path
