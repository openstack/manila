..
      Copyright 2015 Red Hat, Inc.
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

Ganesha Library
===============

The Ganesha Library provides base classes that can be used by drivers to
provision shares via NFS (NFSv3 and NFSv4), utilizing the NFS-Ganesha NFS
server.

Supported operations
--------------------

- Allow NFS Share access

  - Only IP access type is supported.

- Deny NFS Share access

Supported manila drivers
------------------------

- CephFS driver uses ``ganesha.GaneshaNASHelper2`` library class

- GlusterFS driver uses ``ganesha.GaneshaNASHelper`` library class

Requirements
------------

- Preferred:

  `NFS-Ganesha <https://github.com/nfs-ganesha/nfs-ganesha/wiki>`_ v2.4 or
  later, which allows dynamic update of access rules. Use with manila's
  ``ganesha.GaneshaNASHelper2`` class as described later in
  :ref:`using_ganesha_library`.

  (or)

  `NFS-Ganesha <https://github.com/nfs-ganesha/nfs-ganesha/wiki>`_ v2.5.4 or
  later that allows dynamic update of access rules, and can make use of highly
  available Ceph RADOS (distributed object storage) as its shared storage for
  NFS client recovery data, and exports. Use with Ceph v12.2.2 or later, and
  ``ganesha.GaneshaNASHelper2`` library class in manila Queens release or
  later.

- For use with limitations documented in :ref:`ganesha_known_issues`:

  `NFS-Ganesha <https://github.com/nfs-ganesha/nfs-ganesha/wiki>`_ v2.1 to
  v2.3. Use with manila's ``ganesha.GaneshaNASHelper`` class as described later
  in :ref:`using_ganesha_library`.

NFS-Ganesha configuration
-------------------------

The library has just modest requirements against general NFS-Ganesha (in the
following: Ganesha) configuration; a best effort was made to remain agnostic
towards it as much as possible. This section describes the few requirements.

Note that Ganesha's concept of storage backend modules is called FSAL ("File
System Abstraction Layer"). The FSAL the driver intends to leverage needs to be
enabled in Ganesha config.

Beyond that (with default manila config) the following line is needed to be
present in the Ganesha config file (that defaults to
/etc/ganesha/ganesha.conf):

``%include /etc/ganesha/export.d/INDEX.conf``

The above paths can be customized through manila configuration as follows:

- `ganesha_config_dir` = toplevel directory for Ganesha configuration,
     defaults to /etc/ganesha
- `ganesha_config_path` = location of the Ganesha config file, defaults
    to ganesha.conf in `ganesha_config_dir`
- `ganesha_export_dir` = directory where manila generated config bits are
    stored, defaults to `export.d` in `ganesha_config_dir`. The following
    line is required to be included (with value expanded) in the Ganesha
    config file (at `ganesha_config_path`):

    ``%include <ganesha_export_dir>/INDEX.conf``

In versions 2.5.4 or later, Ganesha can store NFS client recovery data in
Ceph RADOS, and also read exports stored in Ceph RADOS. These features are
useful to make Ganesha server that has access to a Ceph (luminous or later)
storage backend, highly available. The Ganesha library class
`GaneshaNASHelper2` (in manila Queens or later) allows you to store Ganesha
exports directly in a shared storage, RADOS objects, by setting the following
manila config options in the driver section:

- `ganesha_rados_store_enable` = 'True' to persist Ganesha exports and export
  counter in Ceph RADOS objects
- `ganesha_rados_store_pool_name` = name of the Ceph RADOS pool to store
  Ganesha exports and export counter objects
- `ganesha_rados_export_index` = name of the Ceph RADOS object used to store
  a list of export RADOS object URLs (defaults to 'ganesha-export-index')

Check out the `cephfs_driver` documentation for an example driver section
that uses these options.

To allow Ganesha to read from RADOS objects add the below code block in
ganesha's configuration file, substituting values per your setup.

.. code-block:: console

    # To read exports from RADOS objects
    RADOS_URLS {
        ceph_conf = "/etc/ceph/ceph.conf";
        userid = "admin";
    }
    # Replace with actual pool name, and export index object
    %url rados://<ganesha_rados_store_pool_name>/<ganesha_rados_export_index>
    # To store client recovery data in the same RADOS pool
    NFSv4 {
        RecoveryBackend = "rados_kv";
    }
    RADOS_KV {
        ceph_conf = "/etc/ceph/ceph.conf";
        userid = "admin";
        # Replace with actual pool name
        pool = <ganesha_rados_store_pool_name>;
    }

For a fresh setup, make sure to create the Ganesha export index object as an
empty object before starting the Ganesha server.

.. code-block:: console

    echo | sudo rados -p ${GANESHA_RADOS_STORE_POOL_NAME} put ganesha-export-index -

Further Ganesha related manila configuration
--------------------------------------------

There are further Ganesha related options in manila (which affect the
behavior of Ganesha, but do not affect how to set up the Ganesha service
itself).

These are:

- `ganesha_service_name` = name of the system service representing Ganesha,
  defaults to ganesha.nfsd
- `ganesha_db_path` = location of on-disk database storing permanent Ganesha
  state, e.g. a export ID counter to generate export IDs for shares

  (or)

  When `ganesha_rados_store_enabled` is set to True, the ganesha export
  counter is stored in a Ceph RADOS object instead of in a SQLite database
  local to the manila driver. The counter can be optionally configured with,
  `ganesha_rados_export_counter` = name of the Ceph RADOS object used as the
  Ganesha export counter (defaults to 'ganesha-export-counter')

- `ganesha_export_template_dir` = directory from where Ganesha loads
    export customizations (cf. "Customizing Ganesha exports").

.. _using_ganesha_library:

Using Ganesha Library in drivers
--------------------------------

A driver that wants to use the Ganesha Library has to inherit
from ``driver.GaneshaMixin``.

The driver has to contain a subclass of ``ganesha.GaneshaNASHelper2``,
instantiate it along with the driver instance and delegate
``update_access`` method to it (when appropriate, i.e., when ``access_proto``
is NFS).

.. note::

    You can also subclass ``ganesha.GaneshaNASHelper``. It works with
    NFS-Ganesha v2.1 to v2.3 that doesn't support dynamic update of exports.
    To update access rules without having to restart NFS-Ganesha server, the
    class manipulates exports created per share access rule (rather than per
    share) introducing limitations documented in :ref:`ganesha_known_issues`.


In the following we explain what has to be implemented by the
``ganesha.GaneshaNASHelper2`` subclass (to which we refer as "helper
class").

Ganesha exports are described by so-called *Ganesha export blocks*
(introduced in the 2.* release series), that is, snippets of Ganesha
config specifying key-pair values.

The Ganesha Library generates sane default export blocks for the
exports it manages, with one thing left blank, the so-called *FSAL
subblock*. The helper class has to implement the ``_fsal_hook``
method which returns the FSAL subblock (in Python represented as
a dict with string keys and values). It has one mandatory key,
``Name``, to which the value should be the name of the FSAL
(eg.: ``{"Name": "CEPH"}``). Further content of it is
optional and FSAL specific.

Customizing Ganesha exports
---------------------------

As noted, the Ganesha Library provides sane general defaults.

However, the driver is allowed to:

- customize defaults
- allow users to customize exports

The config format for Ganesha Library is called *export block
template*. They are syntactically either Ganesha export blocks,
(please consult the Ganesha documentation about the format),
or isomorphic JSON (as Ganesha export blocks are by-and-large
equivalent to arrayless JSON), with two special placeholders
for values: ``@config`` and ``@runtime``. ``@config`` means a
value that shall be filled from manila config, and ``@runtime``
means a value that's filled at runtime with dynamic data.

As an example, we show the library's defaults in JSON format
(also valid Python literal):

  ::

    {
      "EXPORT": {
        "Export_Id": "@runtime",
        "Path": "@runtime",
        "FSAL": {
          "Name": "@config"
        },
        "Pseudo": "@runtime",
        "SecType": "sys",
        "Tag": "@runtime",
        "CLIENT": {
          "Clients": "@runtime",
          "Access_Type": "RW"
        },
        "Squash": "None"
      }
    }

The Ganesha Library takes these values from

*manila/share/drivers/ganesha/conf/00-base-export-template.conf*

where the same data is stored in Ganesha conf format (also supplied with
comments).

For customization, the driver has to extend the ``_default_config_hook``
method as follows:

-  take the result of the super method (a dict representing an export
   block template)
-  set up another export block dict that include your custom values,
   either by

   -  using a predefined export block dict stored in code
   -  loading a predefined export block from the manila source tree
   -  loading an export block from an user exposed location (to allow
      user configuration)

-  merge the two export block dict using the ``ganesha_utils.patch``
   method
-  return the result

With respect to *loading export blocks*, that can be done through the
utility method ``_load_conf_dir``.

Known Restrictions
------------------

- The library does not support network segmented multi-tenancy model but
  instead works over a flat network, where the tenants share a network.

.. _ganesha_known_issues:

Known Issues
------------

Following issues concern only users of `ganesha.GaneshaNASHelper` class that
works with NFS-Ganesha v2.1 to v2.3.

- The export location for shares of a driver that uses the Ganesha Library
  will be of the format ``<ganesha-server>:/share-<share-id>``. However,
  this is incomplete information, because it pertains only to NFSv3
  access, which is partially broken. NFSv4 mounts work well but the
  actual NFSv4 export paths differ from the above. In detail:

  - The export location is usable only for NFSv3 mounts.
  - The export location works only for the first access
    rule that's added for the given share. Tenants that
    should be allowed to access according to a further
    access rule will be refused (cf.
    https://bugs.launchpad.net/manila/+bug/1513061).
  - The share is, however, exported through NFSv4, just
    on paths that differ from the one indicated by
    the export location, namely at:
    ``<ganesha-server>:/share-<share-id>--<access-id>``,
    where ``<access-id>`` ranges over the ID-s of access
    rules of the share (and the export with ``<access-id>``
    is accessible according to the access rule of that ID).
  - NFSv4 access also works with pseudofs. That is, the
    tenant can do a v4 mount of``<ganesha-server>:/`` and
    access the shares allowed for her at the respective
    ``share-<share-id>--<access-id>`` subdirectories.

The :mod:`manila.share.drivers.ganesha` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.ganesha
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
