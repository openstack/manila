..
      Copyright 2014 Mirantis Inc.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Generic approach for share provisioning
=======================================

The Shared File Systems service can be configured to use Nova
VMs and Cinder volumes. There are two modules that handle them in manila:
1) 'service_instance' module creates VMs in Nova with predefined image called
service image. This module can be used by any backend driver for provisioning
of service VMs to be able to separate share resources among tenants.
2) 'generic' module operates with Cinder volumes and VMs created by
'service_instance' module, then creates shared filesystems based on volumes
attached to VMs.

Network configurations
----------------------

Each backend driver can handle networking in its own way,
see: https://wiki.openstack.org/wiki/Manila/Networking

One of two possible configurations can be chosen for share provisioning
    using 'service_instance' module:

- Service VM has one net interface from net that is connected to public router.
  For successful creation of share, user network should be connected to public
  router too.
- Service VM has two net interfaces, first one connected to service network,
  second one connected directly to user's network.

Requirements for service image
------------------------------

- Linux based distro
- NFS server
- Samba server >=3.2.0, that can be configured by data stored in registry
- SSH server
- Two net interfaces configured to DHCP (see network approaches)
- 'exportfs' and 'net conf' libraries used for share actions
- Following files will be used, so if their paths differ one needs to create at
    least symlinks for them:

  * /etc/exports (permanent file with NFS exports)
  * /var/lib/nfs/etab (temporary file with NFS exports used by 'exportfs')
  * /etc/fstab (permanent file with mounted filesystems)
  * /etc/mtab (temporary file with mounted filesystems used by 'mount')

Supported shared filesystems
----------------------------

- NFS (access by IP)
- CIFS (access by IP)

Known restrictions
------------------

- One of Nova's configurations only allows 26 shares per server. This limit
  comes from the maximum number of virtual PCI interfaces that are used for
  block device attaching. There are 28 virtual PCI interfaces, in this
  configuration, two of them are used for server needs and other 26 are used
  for attaching block devices that are used for shares.

- Juno version works only with Neutron. Each share should be created with
  neutron-net and neutron-subnet IDs provided via share-network entity.

- Juno version handles security group, flavor, image, keypair for Nova VM and
  also creates service networks, but does not use availability zones for
  Nova VMs and volume types for Cinder block devices.

- Juno version does not use security services data provided with share-network.
  These data will be just ignored.

- Liberty version adds a share extend capability. Share access will be briefly
  interrupted during an extend operation.

- Liberty version adds a share shrink capability, but this capability is not
  effective because generic driver shrinks only filesystem size and doesn't
  shrink the size of Cinder volume.

The :mod:`manila.share.drivers.generic` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.generic
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.service_instance` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.service_instance
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
