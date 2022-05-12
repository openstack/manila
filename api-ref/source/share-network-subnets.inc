.. -*- rst -*-

Share network subnets (since API v2.51)
=======================================

A share network subnet stores network information to create and manage share
servers.

You can list all subnets that pertain to a share network, also
create, delete and view a share network subnet.

When you create a share network, you may optionally specify an associated
neutron network, subnetwork and an availability zone. If you do not specify an
availability zone, the subnet you are creating will have the availability
zone field empty and this subnet will be considered default. The default subnet
is recognized by the Shared File Systems service as a subnet that spans all
the available storage availability zones.

.. note::
   A share network can have only one default subnet. Likewise, a share network
   cannot have more than one subnet in a given availability zone.

For more information about supported plug-ins for share network subnets,
see `Manila Network Plugins <https://docs.openstack.org/manila/latest/
admin/shared-file-systems-network-plugins.html>`_.

A share network subnet resource has these attributes:

- The IP block in Classless Inter-Domain Routing (CIDR) notation
  from which to allocate the network.

- The IP version of the network.

- The network type, which is ``vlan``, ``vxlan``, ``gre``, or
  ``flat``.

- If the network uses segmentation, a segmentation identifier. For
  example, VLAN, VXLAN, and GRE networks use segmentation.

- The availability zone, when ``null`` signifies that the share network subnet
  is available across all storage availability zones known to the Shared File
  Systems Service.


List share network subnets
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/{share_network_id}/subnets

.. versionadded:: 2.51

Lists all share network subnets in the given share network.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_subnet_id
   - availability_zone: share_network_subnet_availability_zone
   - share_network_id: share_network_subnet_share_network_id
   - share_network_name: share_network_subnet_share_network_name
   - created_at: created_at
   - updated_at: updated_at
   - segmentation_id: share_network_subnet_segmentation_id
   - neutron_net_id: share_network_subnet_neutron_net_id
   - neutron_subnet_id: share_network_subnet_neutron_subnet_id
   - ip_version: share_network_subnet_ip_version
   - cidr: share_network_subnet_cidr
   - network_type: share_network_subnet_network_type
   - gateway: share_network_subnet_gateway
   - mtu: share_network_subnet_mtu

Response example
----------------

.. literalinclude:: samples/share-network-subnet-list-response.json
   :language: javascript


Show share network subnet details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}

.. versionadded:: 2.51

Shows details of a share network subnet.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

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

   - id: share_network_subnet_id
   - neutron_net_id: share_network_subnet_neutron_net_id
   - neutron_subnet_id: share_network_subnet_neutron_subnet_id
   - network_type: share_network_subnet_network_type
   - segmentation_id: share_network_subnet_segmentation_id
   - cidr: share_network_subnet_cidr
   - ip_version: share_network_subnet_ip_version
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_subnet_gateway
   - mtu: share_network_subnet_mtu
   - availability_zone: share_network_subnet_availability_zone
   - share_network_id: share_network_subnet_share_network_id
   - share_network_name: share_network_subnet_share_network_name

Response example
----------------

.. literalinclude:: samples/share-network-subnet-show-response.json
   :language: javascript


Create share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-networks/{share_network_id}/subnets

.. versionadded:: 2.51

Creates a share network subnet in the given share network.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 404
   - 409
   - 500

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path
   - neutron_net_id: neutron_net_id_request
   - neutron_subnet_id: neutron_subnet_id_request
   - availability_zone: availability_zone_request

Request example
---------------

.. literalinclude:: samples/share-network-subnet-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: share_network_subnet_id
   - neutron_net_id: share_network_subnet_neutron_net_id
   - neutron_subnet_id: share_network_subnet_neutron_subnet_id
   - network_type: share_network_subnet_network_type
   - segmentation_id: share_network_subnet_segmentation_id
   - cidr: share_network_subnet_cidr
   - ip_version: share_network_subnet_ip_version
   - created_at: created_at
   - updated_at: updated_at
   - gateway: share_network_subnet_gateway
   - mtu: share_network_subnet_mtu
   - availability_zone: share_network_subnet_availability_zone
   - share_network_id: share_network_subnet_share_network_id
   - share_network_name: share_network_subnet_share_network_name

Response example
----------------

.. literalinclude:: samples/share-network-subnet-create-response.json
   :language: javascript


Delete share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-networks/{share_network_id}/subnets/{share_network_subnet_id}

.. versionadded:: 2.51

Deletes a share network subnet.

Preconditions

- You cannot delete a share network subnet if it has shares created/exported
  on it.

- You cannot delete a share network subnet if it has share servers with the
  flag ``is_auto_deletable`` set to False.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_network_id: share_network_id_path
   - share_network_subnet_id: share_network_subnet_id_path
