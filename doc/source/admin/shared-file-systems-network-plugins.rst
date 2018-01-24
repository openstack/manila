.. _shared_file_systems_network_plugins:

================
Network plug-ins
================

The Shared File Systems service architecture defines an abstraction layer for
network resource provisioning and allowing administrators to choose from a
different options for how network resources are assigned to their projects'
networked storage. There are a set of network plug-ins that provide a variety
of integration approaches with the network services that are available with
OpenStack.

What is a network plugin in Manila?
-----------------------------------

A network plugin is a python class that uses a specific facility (e.g.
Neutron network) to provide network resources to the
:term:`manila-share` service.

When to use a network plugin?
-----------------------------

A Manila `share driver` may be configured in one of two modes, where it is
managing the lifecycle of `share servers` on its own or where it is merely
providing storage resources on a pre-configured share server. This mode
is defined using the boolean option `driver_handles_share_servers` in the
Manila configuration file. A network plugin is only useful when a driver is
handling its own share servers.

.. note::

    Not all share drivers support both modes. Each driver must report which
    mode(s) it supports to the manila-share service.

When `driver_handles_share_servers` is set to `True`, a share driver will be
called to create share servers for shares using information provided within a
`share network`. This information will be provided to one of the enabled
network plugins that will handle reservation, creation and deletion of
network resources including `IP addresses` and `network interfaces`.

The Shared File Systems service may need a network resource provisioning if
share service with specified driver works in mode, when a share driver manages
lifecycle of share servers on its own. This behavior is defined by a flag
``driver_handles_share_servers`` in share service configuration.  When
``driver_handles_share_servers`` is set to ``True``, a share driver will be
called to create share servers for shares using information provided within a
share network. This information will be provided to one of the enabled network
plug-ins that will handle reservation, creation and deletion of network
resources including IP addresses and network interfaces.

What network plug-ins are available?
------------------------------------

There are two network plug-ins and three python classes in the
Shared File Systems service:

#. Network plug-in for using the OpenStack Networking service. It allows to use
   any network segmentation that the Networking service supports. It is up to
   each share driver to support at least one network segmentation type.

   a) ``manila.network.neutron.neutron_network_plugin.NeutronNetworkPlugin``.
      This is a default network plug-in. It requires the ``neutron_net_id`` and
      the ``neutron_subnet_id`` to be provided when defining the share network
      that will be used for the creation of share servers. The user may define
      any number of share networks corresponding to the various physical
      network segments in a project environment.

   b) ``manila.network.neutron.neutron_network_plugin.NeutronSingleNetworkPlugin``.
      This is a simplification of the previous case. It accepts values for
      ``neutron_net_id`` and ``neutron_subnet_id`` from the ``manila.conf``
      configuration file and uses one network for all shares.

   When only a single network is needed, the NeutronSingleNetworkPlugin (1.b)
   is a simple solution. Otherwise NeutronNetworkPlugin (1.a) should be chosen.

#. Network plug-in for specifying networks independently from OpenStack
   networking services.

   a) ``manila.network.standalone_network_plugin.StandaloneNetworkPlugin``.
      This plug-in uses a pre-existing network that is available to the
      manila-share host. This network may be handled either by OpenStack or be
      created independently by any other means. The plug-in supports any type
      of network - flat and segmented. As above, it is completely up to the
      share driver to support the network type for which the network plug-in is
      configured.
