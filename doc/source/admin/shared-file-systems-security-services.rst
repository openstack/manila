.. _shared_file_systems_security_services:

=================
Security services
=================

A security service stores client configuration information used for
authentication and authorization (AuthN/AuthZ). For example, a share server
will be the client for an existing service such as LDAP, Kerberos, or
Microsoft Active Directory.

You can associate a share with one to three security service types:

- ``ldap``: LDAP.

- ``kerberos``: Kerberos.

- ``active_directory``: Microsoft Active Directory.

You can configure a security service with these options:

- A DNS IP address.

- An IP address or host name.

- A domain.

- A user or group name.

- The password for the user, if you specify a user name.

You can add the security service to the
:ref:`share network <shared_file_systems_share_networks>`.

To create a security service, specify the security service type, a
description of a security service, DNS IP address used inside project's
network, security service IP address or host name, domain, security
service user or group used by project, and a password for the user. The
share name is optional.

Create a ``ldap`` security service:

.. code-block:: console

   $ openstack share security service create ldap \
       --dns-ip 8.8.8.8 --server 10.254.0.3 \
       --name my_ldap_security_service
   +-----------------+--------------------------------------+
   | Field           | Value                                |
   +-----------------+--------------------------------------+
   | id              | 266d7c94-db18-47af-b6db-0c3a663e39f5 |
   | name            | my_ldap_security_service             |
   | type            | ldap                                 |
   | status          | new                                  |
   | created_at      | 2025-04-04T12:44:17.131358           |
   | updated_at      | None                                 |
   | description     | None                                 |
   | dns_ip          | 8.8.8.8                              |
   | server          | 10.254.0.3                           |
   | domain          | None                                 |
   | user            | None                                 |
   | password        | None                                 |
   | project_id      | ae096acaa6ce4a3bb4f5a7f7a324514c     |
   | ou              | None                                 |
   | default_ad_site | None                                 |
   +-----------------+--------------------------------------+

To create ``kerberos`` security service, run:

.. code-block:: console

   $ openstack share security service create kerberos \
       --server 10.254.0.3  --user demo --password secret \
       --name my_kerberos_security_service \
       --description "Kerberos security service"
   +-----------------+--------------------------------------+
   | Field           | Value                                |
   +-----------------+--------------------------------------+
   | id              | a6b3634d-63ba-460d-b506-bde475d9c634 |
   | name            | my_kerberos_security_service         |
   | type            | kerberos                             |
   | status          | new                                  |
   | created_at      | 2025-04-04T12:52:24.537002           |
   | updated_at      | None                                 |
   | description     | Kerberos security service            |
   | dns_ip          | None                                 |
   | server          | 10.254.0.3                           |
   | domain          | None                                 |
   | user            | demo                                 |
   | password        | secret                               |
   | project_id      | ae096acaa6ce4a3bb4f5a7f7a324514c     |
   | ou              | None                                 |
   | default_ad_site | None                                 |
   +-----------------+--------------------------------------+

To see the list of created security service use
:command:`openstack share security service list`:

.. code-block:: console

   $ openstack share security service list
   +--------------------------------------+------------------------------+--------+----------+
   | ID                                   | Name                         | Status | Type     |
   +--------------------------------------+------------------------------+--------+----------+
   | 266d7c94-db18-47af-b6db-0c3a663e39f5 | my_ldap_security_service     | new    | ldap     |
   | a6b3634d-63ba-460d-b506-bde475d9c634 | my_kerberos_security_service | new    | kerberos |
   +--------------------------------------+------------------------------+--------+----------+

You can add a security service to the existing
:ref:`share network <shared_file_systems_share_networks>`, which is not
yet used (a ``share network`` not associated with a share).

Add a security service to the share network with
``openstack share network set --new-security-service`` specifying share network
and security service. The command returns information about the
security service. You can see view new attributes and ``share_networks``
using the associated share network ID.

.. code-block:: console

   $ openstack share network set share_net2 \
       --new-security-service my_ldap_security_service

   $ openstack share security service show my_ldap_security_service
   +-----------------+-------------------------------------------+
   | Property        | Value                                     |
   +-----------------+-------------------------------------------+
   | id              | 266d7c94-db18-47af-b6db-0c3a663e39f5      |
   | name            | my_ldap_security_service                  |
   | type            | ldap                                      |
   | status          | new                                       |
   | created_at      | 2025-04-04T12:44:17.131358                |
   | updated_at      | None                                      |
   | description     | None                                      |
   | dns_ip          | 8.8.8.8                                   |
   | server          | 10.254.0.3                                |
   | domain          | None                                      |
   | user            | None                                      |
   | password        | None                                      |
   | project_id      | ae096acaa6ce4a3bb4f5a7f7a324514c          |
   | ou              | None                                      |
   | default_ad_site | None                                      |
   | share_networks  | [u'6d36c41f-d310-4aff-a0c2-ffd870e91cab'] |
   +----------------+--------------------------------------------+

It is possible to see the list of security services associated
with a given share network. List security services for ``share_net2``
share network with:

.. code-block:: console

    $ openstack share network show share_net2
    +-----------------------------------+------------------------------------------------------------+
    | Field                             | Value                                                      |
    +-----------------------------------+------------------------------------------------------------+
    | id                                | 6d36c41f-d310-4aff-a0c2-ffd870e91cab                       |
    | name                              | share_net2                                                 |
    | project_id                        | ae096acaa6ce4a3bb4f5a7f7a324514c                           |
    | created_at                        | 2025-04-03T12:34:12.211349                                 |
    | updated_at                        | None                                                       |
    | description                       | None                                                       |
    | status                            | active                                                     |
    | security_service_update_support   | True                                                       |
    | network_allocation_update_support | True                                                       |
    | share_network_subnets             |                                                            |
    |                                   | id = 55916458-1272-4d41-95d9-b1bfbc2e2da1                  |
    |                                   | availability_zone = None                                   |
    |                                   | created_at = 2025-04-08T21:27:22.735925                    |
    |                                   | updated_at = None                                          |
    |                                   | segmentation_id = None                                     |
    |                                   | neutron_net_id = None                                      |
    |                                   | neutron_subnet_id = None                                   |
    |                                   | ip_version = None                                          |
    |                                   | cidr = None                                                |
    |                                   | network_type = None                                        |
    |                                   | mtu = None                                                 |
    |                                   | gateway = None                                             |
    |                                   | properties =                                               |
    | security_services                 |                                                            |
    |                                   | security_service_name = my_ldap_security_service           |
    |                                   | security_service_id = 266d7c94-db18-47af-b6db-0c3a663e39f5 |
    +-----------------------------------+------------------------------------------------------------+

You also can dissociate a security service from the share network
and confirm that the security service now has an empty list of
share networks:

.. code-block:: console

   $ openstack share network unset --security-service my_ldap_security_service share_net2

   $ openstack share security service show my_ldap_security_service
   +-----------------+--------------------------------------+
   | Property        | Value                                |
   +-----------------+--------------------------------------+
   | id              | 266d7c94-db18-47af-b6db-0c3a663e39f5 |
   | name            | my_ldap_security_service             |
   | type            | ldap                                 |
   | status          | new                                  |
   | created_at      | 2025-04-04T12:44:17.131358           |
   | updated_at      | None                                 |
   | description     | None                                 |
   | dns_ip          | 8.8.8.8                              |
   | server          | 10.254.0.3                           |
   | domain          | None                                 |
   | user            | None                                 |
   | password        | None                                 |
   | project_id      | ae096acaa6ce4a3bb4f5a7f7a324514c     |
   | ou              | None                                 |
   | default_ad_site | None                                 |
   | share_networks  | []                                   |
   +-----------------+--------------------------------------+

The Shared File Systems service allows you to update a security service field
using :command:`openstack share security service set` command with optional
arguments such as ``--dns-ip``, ``--server``, ``--domain``,
``--ou``, ``server``, ``default_ad_site``,
``--user``, ``--password``, ``--name``, or
``--description`` and a required ``security-service`` argument.

To remove a security service not associated with any share networks
run:

.. code-block:: console

   $ openstack share security service delete my_ldap_security_service
