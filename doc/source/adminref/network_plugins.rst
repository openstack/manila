..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Manila Network Plugins
======================

The Manila architecture defines an abstraction layer for network resource
provisioning, and it provides a number of concrete `network plugins`,
allowing administrators to choose from a variety of options for how network
resources are assigned to their tenants' networked storage. This document
describes how network plugins may be configured and used in Manila.

What is a network plugin in Manila?
-----------------------------------

A network plugin is a python class that uses a specific facility (e.g.
Neutron or Nova network) to provide network resources to the
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

As an exception, any share drivers that use Nova for the creation of share
servers should use some wrapper for network plugins, because Nova handles the
creation of network resources for its VMs. In the Manila Kilo version, only
the `Generic driver` uses Nova with the help of its own `network helpers`,
which serve the same needs but are related only to this share driver.

.. _what_network_plugins_are_available:

What network plugins are available?
-----------------------------------

There are three different network plugins and five python classes in Manila:

1 Network plugin for using the `OpenStack` networking project `Neutron`.
  It allows one to use any network segmentation that Neutron supports. It is
  up to each share driver to support at least one network segmentation type.

  1.1 `manila.network.neutron.neutron_network_plugin.NeutronNetworkPlugin`.
    This is the default network plugin. It requires that `neutron_net_id` and
    `neutron_subnet_id` are provided when defining the share network that
    will be used for the creation of share servers.  The user may define any
    number of share networks corresponding to the various physical network
    segments in a tenant environment.

  1.2 `manila.network.neutron.neutron_network_plugin.NeutronSingleNetworkPlugin`.
    This is a simplification of the previous case. It accepts values for
    `neutron_net_id` and `neutron_subnet_id` from the Manila configuration
    file and uses one network for all shares.

  When only a single network is needed, the NeutronSingleNetworkPlugin (1.2)
  is a simple solution. Otherwise NeutronNetworkPlugin (1.1) should be chosen.

2 Network plugin for working with OpenStack native networking from `Nova`.
  It supports either flat networks or VLAN-segmented networks.

  2.1 `manila.network.nova_network_plugin.NovaNetworkPlugin`.
    This plugin serves the networking needs when `Nova networking` is
    configured in the cloud instead of Neutron. It requires a single
    parameter, `nova_net_id`.

  2.2 `manila.network.nova_network_plugin.NovaSingleNetworkPlugin`.
    This one works in the same way as the previous one with one difference.
    It takes nova_net_id from the Manila configuration file and creates
    share servers using only one network.

  When only a single network is needed, the NovaSingleNetworkPlugin (2.2)
  is a simple solution. Otherwise NovaNetworkPlugin (1.1) should be chosen.

3 Network plugin for specifying networks independently from OpenStack
  networking services.

  3.1 `manila.network.standalone_network_plugin.StandaloneNetworkPlugin`.
    This plug-in uses a pre-existing network that is available to the
    manila-share host. This network may be handled either by OpenStack or be
    created independently by any other means. The plugin supports any type of
    network - flat and segmented. As above, it is completely up to the driver
    to support the network type for which the network plugin is configured.

.. note::

    These network plugins were introduced in the OpenStack Kilo release.
    In the OpenStack Juno version, only NeutronNetworkPlugin is available.
    Plugins in 1.2, 2.2, and 3.1 all ignore what the user supplies in the
    share_network and instead always provide IP addresses from a single
    network.

Approaches for setup of network plugins
---------------------------------------

Each manila-share service may have its own network plugin or one that is
shared with other services. All configuration options for network plugins may
be set in three ways by priorities:

- Using a separate configuration group.
    For this case, the config opt `network_config_group` should be defined in
    the config group of the manila-share service and have the name of
    the config group with the defined options for the network plugin.
    First priority.
- Using config group of manila-share service. Second priority.
- Using config group `[DEFAULT]`. Lowest priority.

A specific network plugin is enabled by setting the configuration option
`network_api_class` to one of the values defined in the previous section
:ref:`what_network_plugins_are_available`. This option can be defined in any
of the approaches above along with options for the network plugin itself.

Example of network plugin configuration
---------------------------------------

Let's configure three manila-share services that use different approaches for
configuration of network plugins.
As noted in section :ref:`what_network_plugins_are_available`, in the Kilo
version of OpenStack there are 5 (five) network plugins, three of which
require configuration options - 1.2, 2.2 and 3.1.
We will use a configuration example using network plugin 1.2, the
NeutronSingleNetworkPlugin.

Here is the configuration::

    [DEFAULT]
    enabled_share_backends = SHARE_BACKEND_1,SHARE_BACKEND_2,SHARE_BACKEND_3
    network_api_class = manila.network.neutron.neutron_network_plugin.NeutronSingleNetworkPlugin
    neutron_net_id = neutron_net_id_DEFAULT
    neutron_subnet_id = neutron_subnet_id_DEFAULT

    [NETWORK_PLUGIN]
    neutron_net_id = neutron_net_id_NETWORK_PLUGIN
    neutron_subnet_id = neutron_subnet_id_NETWORK_PLUGIN

    [SHARE_BACKEND_1]
    # This share backend is enabled for handling of share servers using opts
    # for network plugin defined in separate config group called `NETWORK_PLUGIN`.
    network_config_group = NETWORK_PLUGIN
    driver_handles_share_servers = True

    [SHARE_BACKEND_2]
    # This share backend is enabled for handling of share servers using opts
    # defined in its own config group.
    driver_handles_share_servers = True
    neutron_net_id = neutron_net_id_SHARE_BACKEND_2
    neutron_subnet_id = neutron_subnet_id_SHARE_BACKEND_2

    [SHARE_BACKEND_3]
    # This share backend is enabled for handling of share servers using opts
    # defined in config group [DEFAULT].
    driver_handles_share_servers = True

Here is a list of neutron_net_id and neutron_subnet_id values for our
manila-share services:

- [SHARE_BACKEND_1]
    - neutron_net_id=neutron_net_id_NETWORK_PLUGIN
    - neutron_subnet_id=neutron_subnet_id_NETWORK_PLUGIN
- [SHARE_BACKEND_2]
    - neutron_net_id=neutron_net_idSHARE_BACKEND_2
    - neutron_subnet_id=neutron_subnet_id_SHARE_BACKEND_2
- [SHARE_BACKEND_3]
    - neutron_net_id=neutron_net_id_DEFAULT
    - neutron_subnet_id=neutron_subnet_id_DEFAULT

The value for option network_api_class was taken by each manila-share service
from group [DEFAULT] because it was not redefined in other places.

.. note::

    The last approach - use of [DEFAULT] group - is not preferred for setting
    network plugin options and will generate warnings in your manila-share
    logs. Either of the first two approaches is recommended.
