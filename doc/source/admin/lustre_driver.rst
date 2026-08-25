..
      Copyright 2026 Red Hat, Inc.
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

=============
Lustre driver
=============

The Lustre driver creates shares as sub-directories on a pre-provisioned
`Lustre <https://www.lustre.org/>`_ parallel filesystem. Capacity is
enforced with `project quotas
<https://doc.lustre.org/lustre_manual.xhtml#managingprojectquotas>`_
and access control uses `nodemaps
<https://doc.lustre.org/lustre_manual.xhtml#lustrenodemap>`_ for
IP-based client isolation.

The driver operates in DHSS=False mode only (the Lustre filesystem
must be provisioned and mounted before Manila starts).

Prerequisites
~~~~~~~~~~~~~

- Lustre >= 2.16 (required for RBAC nodemaps and ``root_prj_enable``).
- A mounted Lustre client on the manila-share host.
- Project quotas enabled on all MDTs and OSTs.
- Nodemap feature activated on the MGS.
- ``lfs`` and ``lctl`` utilities available on the manila-share host.

For details on installing and configuring a Lustre filesystem, see the
`Lustre Operations Manual <https://doc.lustre.org/lustre_manual.xhtml>`_.

Supported operations
~~~~~~~~~~~~~~~~~~~~

The driver supports the LUSTRE protocol with IP access rules.

- Create and delete a share
- Extend and shrink a share
- Allow and deny share access (IP type, RW and RO)
- Manage and unmanage an existing share

Restrictions
~~~~~~~~~~~~

- Only ``ip`` access type is supported.
- Snapshots are not supported (Lustre does not have
  filesystem-level snapshots).
- Share groups and replication are not supported.
- IPv6 access rules are not currently supported.

Back-end configuration
~~~~~~~~~~~~~~~~~~~~~~

Add LUSTRE to the enabled share protocols:

.. code-block:: ini

    [DEFAULT]
    enabled_share_protocols = LUSTRE

Create a backend section in ``manila.conf``:

.. code-block:: ini

    [lustre1]
    share_driver = manila.share.drivers.lustre.driver.LustreShareDriver
    driver_handles_share_servers = False
    share_backend_name = LUSTRE1
    lustre_share_export_ip = 10.0.0.5
    lustre_mount_point = /mnt/lustre
    lustre_fs_name = lustrefs

Add the backend to ``enabled_share_backends``:

.. code-block:: ini

    [DEFAULT]
    enabled_share_backends = lustre1

When the MGS or MDS is on a different host, configure SSH access:

.. code-block:: ini

    [lustre1]
    lustre_mgs_ip = 10.0.0.10
    lustre_mds_ip = 10.0.0.11
    lustre_ssh_username = root
    lustre_ssh_private_key_path = /etc/manila/lustre_ssh_key

When both MGS and MDS run on the manila-share host, omit
``lustre_mgs_ip`` and ``lustre_mds_ip`` and the driver will use
oslo.privsep for privileged operations.

Project ID range
----------------

Each share is assigned a unique Lustre project ID for quota
enforcement. The range is controlled by ``lustre_project_id_start``
(default 10000) and ``lustre_project_id_end`` (default 60000).
Ensure this range does not overlap with project IDs used by other
applications on the same filesystem.

Share types
~~~~~~~~~~~

Create a share type for Lustre shares:

.. code-block:: console

    openstack share type create lustretype false
    openstack share type set lustretype \
        --extra-specs vendor_name=Lustre storage_protocol=LUSTRE

Create a share:

.. code-block:: console

    openstack share create --share-type lustretype --name myshare lustre 10

Mounting shares
~~~~~~~~~~~~~~~

The export location is in Lustre NID format::

    <nid>:/<fsname>/<path>

Mount using the Lustre client:

.. code-block:: console

    sudo mount -t lustre 10.0.0.5@tcp:/lustrefs/manila_shares/share-xyz /mnt/myshare

For client mount instructions, see the
`Lustre Operations Manual: Mounting
<https://doc.lustre.org/lustre_manual.xhtml#mountinglustre>`_.

Access control
~~~~~~~~~~~~~~

The driver creates a Lustre nodemap per access rule, mapping the
client IP (or CIDR) to the share's sub-directory. Read-only rules
set ``readonly_mount=1`` on the nodemap. Nodemaps persist on the
MGS across reboots.

See `Lustre Nodemap documentation
<https://doc.lustre.org/lustre_manual.xhtml#lustrenodemap>`_ for
background on how nodemaps enforce client identity and permissions.

Driver options
~~~~~~~~~~~~~~

All configuration options for the Lustre driver are documented in the
:doc:`Configuration Reference </configuration/shared-file-systems/config-reference>`.
