..
      Copyright 2026 Weka.IO Ltd.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

=================
Weka Share Driver
=================

The Weka share driver allows OpenStack Manila to use
`Weka <https://www.weka.io/>`_ as a shared-file-system backend.  It exposes
Weka filesystems as Manila shares and supports two access protocols:

* **WEKAFS** (primary) -- the WekaFS POSIX kernel client mounted directly on
  the Manila host.  Delivers sub-250 us latency and full POSIX semantics.
  Requires the WekaFS kernel module to be installed on the Manila host.
* **NFS** (secondary) -- standard NFS v3 exports via Weka's built-in NFS
  gateway.  Works on all Linux kernel versions with no additional client
  software.

The driver operates in ``driver_handles_share_servers=False`` mode and maps
each Manila share to one Weka filesystem.

.. note::

   The WekaFS kernel module does not compile on Linux kernel 6.17 or later
   due to a breaking change in ``inode_operations``.  Use the NFS protocol or
   pin the host kernel below 6.17 when running on affected distributions.

Architecture
------------

::

     Manila ShareDriver API
            |
            v
     WekaShareDriver  (manila/share/drivers/weka/driver.py)
            |
            +-- WekaApiClient  -- REST calls to the Weka cluster (port 14000)
            |
            +-- WekaMount      -- WekaFS POSIX mount management on the host
            |
            +-- privsep        -- mount/umount/rsync as root

Implementation notes that matter when reading or extending the driver:

* All Weka API calls exchange **bytes**; conversion to and from GiB happens
  in the driver.
* Every create and delete is idempotent -- already-exists and not-found
  conditions are handled silently, so a retried request converges.
* The Manila share UUID is the Weka filesystem name, prefixed with
  ``weka_share_name_prefix``.
* The Weka filesystem UID is recorded in the share's export metadata, so
  later operations resolve the filesystem directly instead of scanning
  every filesystem on the cluster.

WEKAFS Tenant Isolation
~~~~~~~~~~~~~~~~~~~~~~~

WEKAFS shares are isolated per tenant, and the isolation is mandatory --
there is no option to disable it.  Each Manila project is mapped to its own
Weka organization named ``<weka_org_prefix><project_id>``, and WEKAFS
filesystems are created inside that organization with authentication
required.  A mount token scoped to one project therefore cannot mount
another project's shares: the boundary is enforced by the Weka cluster, not
by the driver.

This requires a multi-tenant Weka cluster and the ``weka_org_admin_secret``
option.  Each organization's admin password is derived deterministically as
``HMAC-SHA256(weka_org_admin_secret, project_id)``, so the driver stores no
per-tenant secret.  The driver refuses to start when the secret is unset.

.. warning::

   Keep ``weka_org_admin_secret`` stable.  Rotating it changes every derived
   password and invalidates the logins of organizations already created.

Within the organization the driver also creates a least-privilege *mount
user* named ``<weka_org_user>-mnt``.  Its password is returned to the tenant
as the ``access_key`` of each WEKAFS access rule, so tenants mount their own
shares with no operator hand-off.

Prerequisites
-------------

* **Weka cluster** version 5.0 or later (tested against 5.1.x), configured
  for multi-tenancy (required for WEKAFS shares).
* **OpenStack Manila** — the driver is introduced in the Hibiscus
  release.
* Network connectivity from the Manila host to the Weka cluster on TCP
  port **14000** (REST API).
* For WEKAFS protocol shares only: the WekaFS client package must be
  installed on the Manila host and the ``wekafsio`` kernel module loaded:

  .. code-block:: console

     $ sudo modprobe wekafsio
     $ lsmod | grep wekafsio   # verify

Supported Operations
--------------------

* Create and delete shares
* Extend and shrink shares
* Ensure shares (re-mount on service restart)
* Create, delete, and revert-to snapshots
* Create shares from snapshots
* Manage and unmanage existing shares
* Report share statistics and capacity

Access Rules
~~~~~~~~~~~~

For WEKAFS shares, each ``ip`` rule is mapped to a per-filesystem Weka
security policy that admits only the client source addresses it names and
denies all others at native mount time.  ``--access-level`` is honored: an
``ro`` rule installs a read-only policy.

Alternatively, a share type may reference a shared, reusable policy group
through the ``weka:security_policy_group`` extra spec, whose contents are
defined by the ``weka_security_policy_group`` configuration option.  One
policy object then serves every share of that type, which keeps a large
deployment within the cluster's policy budget.

NFS shares use IP-based access rules backed by Weka client groups and export
permissions.

For both protocols, ``ip`` rules are IPv4-only.  The driver reports
``ipv6_implemented = False``, and an IPv6 rule that reaches it anyway
is logged and ignored rather than applied.

Access Rule Reconciliation
^^^^^^^^^^^^^^^^^^^^^^^^^^

``update_access`` honors both modes of the Manila driver contract.  In
incremental mode the driver applies ``add_rules``, ``delete_rules`` and
``update_rules``.  When ``add_rules`` and ``delete_rules`` are both empty --
as they are when the access level changes for every rule on a share -- the
driver instead reconciles the backend down to ``access_rules``, removing the
export permissions, client groups and security-policy addresses that no
longer correspond to a rule.  A revoked rule therefore cannot leave working
access behind on the cluster.

Shares whose share type sets ``weka:security_policy_group`` are exempt from
reconciliation: those policies are shared between shares, so reconciling one
share's rules against them would revoke access for the others.

Configuration
-------------

The driver ships with Manila; no separate installation is required.  Enable
it by adding a Weka backend section to ``manila.conf`` (see below).

Install WekaFS Kernel Module (WEKAFS protocol only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Download and install the WekaFS client package from your Weka cluster:

.. code-block:: console

   $ curl -k -o weka-client.tar \
         https://<weka-ip>:14000/dist/v1/install/<weka-version>
   $ tar xf weka-client.tar
   $ sudo ./install.sh
   $ sudo modprobe wekafsio
   $ echo "wekafsio" | sudo tee /etc/modules-load.d/wekafs.conf

Configure ``manila.conf``
~~~~~~~~~~~~~~~~~~~~~~~~~

Add a ``[weka]`` backend section to ``manila.conf``:

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = weka
   enabled_share_protocols = NFS,WEKAFS

   [weka]
   share_driver = manila.share.drivers.weka.driver.WekaShareDriver
   share_backend_name = weka
   driver_handles_share_servers = false

   # Connection
   weka_api_server      = weka-cluster.example.com
   weka_api_port        = 14000
   weka_ssl_verify      = true

   # Authentication
   weka_username        = manila-driver
   weka_password        = your-password-here
   weka_organization    = Root

   # WEKAFS per-tenant isolation (required for WEKAFS shares)
   weka_org_admin_secret = a-long-random-secret

   # Filesystem management
   weka_filesystem_group  = default
   weka_share_name_prefix = manila_

   # POSIX client (WEKAFS protocol only)
   weka_mount_point_base  = /mnt/weka
   weka_num_cores         = 1

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

The driver's options are registered in ``manila/opts.py``, so the full
list with types and defaults is rendered into the sample ``manila.conf``
and the configuration reference.

Share Type Extra Specs
~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Extra Spec
     - Description
   * - ``weka:security_policy_group``
     - Name of a group defined in ``weka_security_policy_group``.  WEKAFS
       shares of this type are created with the group's Allow policies
       attached and are exempt from per-share rule reconciliation.

Known Limitations
-----------------

* ``ip`` access rules are IPv4-only on both protocols.  An IPv6 rule is
  reported in the ``error`` state rather than applied.
* WEKAFS shares require a multi-tenant Weka cluster.  Tenant isolation
  cannot be turned off.
* Shares are thick-provisioned (the filesystem reserves its full size).
  Thin provisioning and QoS are planned as future enhancements, exposed
  through share-type extra specs.
* ``create_share_from_snapshot`` runs asynchronously: the share is
  reported ``creating_from_snapshot`` until the data copy completes.  The
  copy uses the WekaFS POSIX client for WEKAFS shares and ``rsync`` over
  the NFS gateway for NFS shares, so copy time scales with snapshot size.
  If ``manila-share`` restarts mid-copy the in-memory progress is lost and
  the share is reported ``error``; delete it and retry.
* The WekaFS kernel module is incompatible with Linux kernel 6.17 or
  later.  Use the NFS protocol or pin the host kernel below 6.17.

Troubleshooting
---------------

``WekaMountError: mount command failed``
   The WekaFS kernel module is not loaded.  Run ``modprobe wekafsio``.

``WekaAuthError: Weka authentication failed``
   Verify ``weka_username``, ``weka_password``, and ``weka_organization``
   in ``manila.conf``.

``WekaConfigurationError: weka_org_admin_secret must be set``
   WEKAFS shares are always created with per-tenant organization isolation,
   which derives per-org credentials from this secret.  Set
   ``weka_org_admin_secret`` in the backend section and restart
   ``manila-share``.

``ShareShrinkingPossibleDataLoss``
   The filesystem contains more data than the requested target size.
   Free space on the share before shrinking.

``FileSystemNotFound`` errors in ``ensure_share``
   The Weka filesystem was deleted outside Manila.  Either restore it or
   remove the share from Manila with ``openstack share delete <share>``.
