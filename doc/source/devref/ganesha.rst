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

Requirements
------------

`NFS-Ganesha <https://github.com/nfs-ganesha/nfs-ganesha/wiki>`__ 2.1 or newer.

NFS-Ganesha configuration
-------------------------

The library has just modest requirements against general NFS-Ganesha (in the
following: Ganesha) configuration; a best effort was made to remain agnostic
towards it as much as possible. This section describes the few requirements.

Note that Ganesha's concept of storage backend modules is called FSAL ("File
System Abstraction Layer"). The FSAL the driver intends to leverage needs to be
enabled in Ganesha config.

Beyond that (with default Manila config) the following line is needed to be
present in the Ganesha config file (that defaults to
/etc/ganesha/ganesha.conf):

``%include /etc/ganesha/export.d/INDEX.conf``

The above paths can be customized through Manila configuration as follows:

- `ganesha_config_dir` = toplevel directory for Ganesha configuration,
     defaults to /etc/ganesha
- `ganesha_config_path` = location of the Ganesha config file, defaults
    to ganesha.conf in `ganesha_config_dir`
- `ganesha_export_dir` = directory where Manila generated config bits are
    stored, defaults to `export.d` in `ganesha_config_dir`. The following
    line is required to be included (with value expanded) in the Ganesha
    config file (at `ganesha_config_path`):

    ``%include <ganesha_export_dir>/INDEX.conf``


Further Ganesha related Manila configuration
--------------------------------------------

There are further Ganesha related options in Manila (which affect the
behavior of Ganesha, but do not affect how to set up the Ganesha service
itself).

These are:

- `ganesha_service_name` = name of the system service representing Ganesha,
    defaults to ganesha.nfsd
- `ganesha_db_path` = location of on-disk database storing permanent Ganesha
    state
- `ganesha_export_template_dir` = directory from where Ganesha loads
    export customizations (cf. "Customizing Ganesha exports").

Using Ganesha Library in drivers
--------------------------------

A driver that wants to use the Ganesha Library has to inherit
from ``driver.GaneshaMixin``.

The driver has to contain a subclass of ``ganesha.GaneshaNASHelper``,
instantiate it along with the driver instance and delegate
``allow_access`` and ``deny_access`` methods to it (when appropriate,
ie. when ``access_proto`` is NFS).

In the following we explain what has to be implemented by the
``ganesha.GaneshaNASHelper`` subclass (to which we refer as "helper
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
(eg.: ``{"Name": "GLUSTER"}``). Further content of it is
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
value that shall be filled from Manila config, and ``@runtime``
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
   -  loading a predefined export block from the Manila source tree
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

.. _ganesha_known_issues

Known Issues
------------

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
