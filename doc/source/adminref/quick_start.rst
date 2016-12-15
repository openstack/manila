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

Quick start
===========
This document describes how to install manila from the OpenStack `Mitaka`
release. Note that the process differs from previous releases and is likely to
change again in subsequent releases.

Manila consists of the following main services, which are similar to those of
the OpenStack cinder project:

- manila-api
- manila-data
- manila-scheduler
- manila-share

Installations of `manila-api` and `manila-scheduler` are common
for almost all deployments. But configuration of `manila-share` is
backend-specific and can differ from deployment to deployment. This
document will cover only a single use case, configuring the "Generic" driver
that uses the cinder project as its backend.

Note that the `manila-share` service can run in two modes, with and without
handling of `share servers`.  In most cases share servers are virtual machines
that export file shares via various network file systems. The example in this
document describes a backend that manages share servers using network resources
provided by neutron.

.. note::
    Manila supports any network architecture. When a driver is managing its own
    share servers, it can use any of several network plug-ins that provide
    network resources. Manila includes plug-ins for neutron and nova-network,
    as well as a `StandaloneNetworkPlugin` for simple networks. When a driver
    is not managing share servers, it has no need for network plug-ins.

Prerequisites
-------------
- MySQL database
- RabbitMQ message bus
- OpenStack keystone
- Git

For Generic driver:

- OpenStack cinder
- OpenStack glance
- OpenStack neutron
- OpenStack nova

Steps to perform
================
- Installation of manila binaries
- Installation of manila client
- Registration in keystone
- Preparation of external files (configs, etc...)
- Basic configuration of manila
- Database setup
- Running manila services
- Creation of pilot share

Installation of manila binaries
-------------------------------
Manila binaries may be installed using various distribution packages or from
source code. In our case we will use the latter, installation by cloning a git
repository.

Clone repo::

    $ git clone -b stable/mitaka https://github.com/openstack/manila

Then run the installation script::

    $ sudo python setup.py install

It will install the manila binaries and their dependencies.
These are the expected binaries:

- manila-all
- manila-api
- manila-data
- manila-manage
- manila-scheduler
- manila-share

Installation of manila client
-----------------------------

To send requests to manila we need to install the manila client.

Install it using PIP:

.. code-block:: console

    $ sudo pip install python-manilaclient>=1.8.1

.. note::
    The starting version of the manila client for Mitaka release is 1.8.1

The above will install the manila binary that will be used for issuing
manila requests.

Registration in keystone
------------------------

Like all other OpenStack projects, manila should be registered with keystone.
Here are the registration steps, similar to those of cinder:

1) Create manila service user:

.. code-block:: console

    $ openstack user create --password %PASSWORD% manila

2) Add the admin role to the manila user:

.. code-block:: console

    $ openstack role add --user manila --project service admin

.. note::
    Tenant/project may differ, but it should be the same as for all other
    service users such as ‘cinder’, ‘nova’, etc.

3) Create the manila service entities:

.. code-block:: console

    $ openstack service create \
        --name manila \
        --description "OpenStack Shared Filesystems"\
        share

    $ openstack service create \
        --name manilav2 \
        --description "OpenStack Shared Filesystems V2"\
        sharev2


Result::

    +-------------+----------------------------------+
    |   Property  |              Value               |
    +-------------+----------------------------------+
    | description |   OpenStack Shared Filesystems   |
    |   enabled   |               True               |
    |      id     | 4c13e9ff7ec04f4e95a26f72ecdf9919 |
    |     name    |              manila              |
    |     type    |              share               |
    +-------------+----------------------------------+

    +-------------+----------------------------------+
    |   Property  |              Value               |
    +-------------+----------------------------------+
    | description | OpenStack Shared Filesystems V2  |
    |   enabled   |               True               |
    |      id     | 2840d1e7b033437f8776a7bd5045b28d |
    |     name    |             manilav2             |
    |     type    |             sharev2              |
    +-------------+----------------------------------+


4) Create the Share Filesystems service API endpoints:

.. code-block:: console

    $ openstack endpoint create \
        --region RegionOne \
        --publicurl http://%controller%:8786/v1/%\(tenant_id\)s \
        --internalurl http://%controller%:8786/v1/%\(tenant_id\)s \
        --adminurl http://%controller%:8786/v1/%\(tenant_id\)s \
        share


Result should be similar to::

    +--------------+--------------------------------------------------------------+
    | Field        | Value                                                        |
    +--------------+--------------------------------------------------------------+
    | adminurl     | http://%controller%:8786/v1/%(tenant_id)s                    |
    | id           | 118230f5aa514809a9866ae411636b43                             |
    | internalurl  | http://%controller%:8786/v1/%(tenant_id)s                    |
    | publicurl    | http://%controller%:8786/v1/%(tenant_id)s                    |
    | region       | RegionOne                                                    |
    | service_id   | 4c13e9ff7ec04f4e95a26f72ecdf9919                             |
    | service_name | manila                                                       |
    | service_type | share                                                        |
    +--------------+--------------------------------------------------------------+

    $ openstack endpoint create \
        --region RegionOne \
        --publicurl http://%controller%:8786/v2/%\(tenant_id\)s \
        --internalurl http://%controller%:8786/v2/%\(tenant_id\)s \
        --adminurl http://%controller%:8786/v2/%\(tenant_id\)s \
        sharev2


Result should be similar to::

    +--------------+--------------------------------------------------------------+
    | Field        | Value                                                        |
    +--------------+--------------------------------------------------------------+
    | adminurl     | http://%controller%:8786/v2/%(tenant_id)s                    |
    | id           | 228230f5aa514809a9866ae411636b8d                             |
    | internalurl  | http://%controller%:8786/v2/%(tenant_id)s                    |
    | publicurl    | http://%controller%:8786/v2/%(tenant_id)s                    |
    | region       | RegionOne                                                    |
    | service_id   | 2840d1e7b033437f8776a7bd5045b28d                             |
    | service_name | manilav2                                                     |
    | service_type | sharev2                                                      |
    +--------------+--------------------------------------------------------------+

.. note::
    Port ‘8786’ is the default port for manila. It may be changed to any
    other port, but this change should also be made in the manila configuration
    file using opt ‘osapi_share_listen_port’ which defaults to ‘8786’.

Preparation of external files
-----------------------------
Copy files from %git_dir%/etc/manila
to dir ‘/etc/manila’::

    policy.json
    api-paste.ini
    rootwrap.conf
    rootwrap.d/share.filters


Then generate a config sample file using tox:

.. code-block:: console

    $ tox -e genconfig

This will create a file with the latest config options and their descriptions::

    ‘%git_dir%/etc/manila/manila.conf.sample’

Copy this file to the same directory as the above files, removing the suffix
‘.sample’ from its name:

.. code-block:: console

    $ cp %git_dir%/etc/manila/manila.conf.sample /etc/manila/manila.conf

.. note::
    Manila configuration file may be used from different places.
    `/etc/manila/manila.conf` is one of expected paths by default.

Basic configuration of manila
-----------------------------
In our case we will set up one backend with generic driver (using cinder
as its backend) configured to manage its own share servers.
Below is an example of the configuration file, `/etc/manila/manila.conf`,
outlining some core sections.

.. code-block:: ini

    [keystone_authtoken]
    signing_dir = /var/cache/manila
    admin_password = %password_we_used_with_user_creation_operation%
    admin_user = manila
    admin_tenant_name = %service_project_name_we_used_with_user_creation_operation%
    auth_protocol = http
    auth_port = 35357
    auth_host = %address_of_machine_with_keystone_endpoint%

    [DATABASE]
    # Set up MySQL connection. In following  ‘foo’ is username,
    # ‘bar’ is password and ‘quuz’ is host name or address:
    connection = mysql+pymysql://foo:bar@quuz/manila?charset=utf8

    [oslo_concurrency]
    # Following opt defines directory to be used for lock files creation.
    # Should be owned by user that runs manila-share processes.
    # Defaults to env var ‘OSLO_LOCK_PATH’. It is used by manila-share services
    # and is required to be set up. Make sure this dir is created and owned
    # by user that run manila-share services.
    lock_path = /etc/manila/custom_manila_lock_path

    [DEFAULT]
    # Set pretty logging output. Not required, but may be useful.
    logging_exception_prefix = %(color)s%(asctime)s.%(msecs)d TRACE %(name)s ^[[01;35m%(instance)s^[[00m
    logging_debug_format_suffix = ^[[00;33mfrom (pid=%(process)d) %(funcName)s %(pathname)s:%(lineno)d^[[00m
    logging_default_format_string = %(asctime)s.%(msecs)d %(color)s%(levelname)s %(name)s [^[[00;36m-%(color)s] ^[[01;35m%(instance)s%(color)s%(message)s^[[00m
    logging_context_format_string = %(asctime)s.%(msecs)d %(color)s%(levelname)s %(name)s [^[[01;36m%(request_id)s ^[[00;36m%(user_id)s %(project_id)s%(color)s] ^[[01;35m%(instance)s%(color)s%(message)s^[[00m

    # Set auth strategy for usage of keystone
    auth_strategy = keystone

    # Set message bus creds
    rabbit_userid = %rabbit_username%
    rabbit_password = %rabbit_user_password%
    rabbit_hosts = %address_of_machine_with_rabbit%
    rpc_backend = rabbit

    # Following opt is used for definition of share backends that should be enabled.
    # Values are conf groupnames that contain per manila-share service opts.
    enabled_share_backends = london

    # Enable protocols ‘NFS’ and ‘CIFS’ as those are the only supported
    # by Generic driver that we are configuring in this set up.
    # All available values are (‘NFS’, ‘CIFS’, ‘GlusterFS’, ‘HDFS’, 'CEPHFS', ‘MapRFS’)
    enabled_share_protocols = NFS,CIFS

    # Manila requires ‘share-type’ for share creation.
    # So, set here name of some share-type that will be used by default.
    default_share_type = default_share_type

    state_path = /opt/stack/data/manila
    osapi_share_extension = manila.api.contrib.standard_extensions
    rootwrap_config = /etc/manila/rootwrap.conf
    api_paste_config = /etc/manila/api-paste.ini
    share_name_template = share-%s

    # Set scheduler driver with usage of filters. Recommended.
    scheduler_driver = manila.scheduler.drivers.filter.FilterScheduler

    # Set following opt to ‘True’ to get more info in logging.
    debug = True

    [nova]
    # Only needed by generic or windows drivers, the only drivers
    # as of Mitaka that require it.
    username = nova
    password = %password%
    project_domain_id = default
    project_name = service
    user_domain_id = default
    auth_url = http://127.0.0.1:5000
    auth_type = password

    [neutron]
    # Only needed when the networking drivers use nova and "generic" driver,
    # as used in this example.
    username = neutron
    password = %password%
    project_domain_id = default
    project_name = service
    user_domain_id = default
    auth_url = http://127.0.0.1:5000
    auth_type = password

    [cinder]
    # Only needed by generic or windows drivers, the only drivers
    # as of Mitaka that require it.
    username = cinder
    password = %password%
    project_domain_id = default
    project_name = service
    user_domain_id = default
    auth_url = http://127.0.0.1:5000
    auth_type = password

    [london]
    # This is custom opt group that is used for storing opts of share-service.
    # This one is used only when enabled using opt `enabled_share_backends`
    # from DEFAULT group.

    # Set usage of Generic driver which uses cinder as backend.
    share_driver = manila.share.drivers.generic.GenericShareDriver

    # Generic driver supports both driver modes - with and without handling
    # of share servers. So, we need to define explicitly which one we are
    # enabling using this driver.
    driver_handles_share_servers = True

    # Generic driver uses a glance image for building service VMs in nova.
    # The following options specify the image to use.
    # We use the latest build of [1].
    # [1] https://github.com/openstack/manila-image-elements
    service_instance_password = manila
    service_instance_user = manila
    service_image_name = manila-service-image

    # These will be used for keypair creation and inserted into service VMs.
    path_to_private_key = /home/stack/.ssh/id_rsa
    path_to_public_key = /home/stack/.ssh/id_rsa.pub

    # Custom name for share backend.
    share_backend_name = LONDON

.. note::
    The Generic driver does not use network plugins, so none is part of the
    above configuration. Other drivers that manage their own share servers may
    require one of manila's network plug-ins.

Database setup
--------------
Manila supports different SQL dialects in theory, but it is only tested with
MySQL, so this step assumes that MySQL has been installed.

Create the database for manila:

.. code-block:: console

    $ mysql -u%DATABASE_USER% -p%DATABASE_PASSWORD% -h%MYSQL_HOST% -e "DROP DATABASE IF EXISTS manila;"
    $ mysql -u%DATABASE_USER% -p%DATABASE_PASSWORD% -h%MYSQL_HOST% -e "CREATE DATABASE manila CHARACTER SET utf8;"

Then create manila's tables and apply all migrations:

.. code-block:: console

    $ manila-manage db sync

Here is the list of tables for the Mitaka release of manila::

    +--------------------------------------------+
    | Tables_in_manila                           |
    +--------------------------------------------+
    | alembic_version                            |
    | availability_zones                         |
    | cgsnapshot_members                         |
    | cgsnapshots                                |
    | consistency_group_share_type_mappings      |
    | consistency_groups                         |
    | drivers_private_data                       |
    | network_allocations                        |
    | project_user_quotas                        |
    | quota_classes                              |
    | quota_usages                               |
    | quotas                                     |
    | reservations                               |
    | security_services                          |
    | services                                   |
    | share_access_map                           |
    | share_instance_access_map                  |
    | share_instance_export_locations            |
    | share_instance_export_locations_metadata   |
    | share_instances                            |
    | share_metadata                             |
    | share_network_security_service_association |
    | share_networks                             |
    | share_server_backend_details               |
    | share_servers                              |
    | share_snapshot_instances                   |
    | share_snapshots                            |
    | share_type_extra_specs                     |
    | share_type_projects                        |
    | share_types                                |
    | shares                                     |
    +--------------------------------------------+

Running manila services
-----------------------

Run manila-api first:

.. code-block:: console

    $ manila-api \
        --config-file /etc/manila/manila.conf & \
        echo $! >/opt/stack/status/stack/m-api.pid; \
        fg || echo "m-api failed to start" | \
        tee "/opt/stack/status/stack/m-api.failure"

Create a default share type before running `manila-share` service:

.. code-block:: console

    $ manila type-create default_share_type True

Where `default_share_type` is custom name of `share-type` and `True` is value
for required extra-spec `driver_handles_share_servers`. These are required
params for creation of `share-type`.

Result::

    +----------------------+-------------------------------------+
    | Property             | Value                               |
    +----------------------+-------------------------------------+
    | required_extra_specs | driver_handles_share_servers : True |
    | Name                 | default_share_type                  |
    | Visibility           | public                              |
    | is_default           | -                                   |
    | ID                   | %some_id%                           |
    | optional_extra_specs | snapshot_support : True             |
    +----------------------+-------------------------------------+

Service `manila-api` may be restarted to get updated information about
`default share type`. So, get list of share types after restart of
service `manila-api`:

.. code-block:: console

    $ manila type-list

Result::

    +-----------+--------------------+------------+------------+-------------------------------------+-------------------------+
    | ID        | Name               | visibility | is_default | required_extra_specs                | optional_extra_specs    |
    +-----------+--------------------+------------+------------+-------------------------------------+-------------------------+
    | %some_id% | default_share_type | public     | YES        | driver_handles_share_servers : True | snapshot_support : True |
    +-----------+--------------------+------------+------------+-------------------------------------+-------------------------+


Add any additional extra specs to `share-type` if needed using following command:

.. code-block:: console

    $ manila type-key default_share_type set key=value

This may be viewed as follows:

.. code-block:: console

    $ manila extra-specs-list

Run manila-scheduler:

.. code-block:: console

    $ manila-scheduler \
        --config-file /etc/manila/manila.conf & \
        echo $! >/opt/stack/status/stack/m-sch.pid; \
        fg || echo "m-sch failed to start" | \
        tee "/opt/stack/status/stack/m-sch.failure"

Run manila-share:

.. code-block:: console

    $ manila-share \
        --config-file /etc/manila/manila.conf & \
        echo $! >/opt/stack/status/stack/m-shr.pid; \
        fg || echo "m-shr failed to start" | \
        tee "/opt/stack/status/stack/m-shr.failure"

Run manila-data:

.. code-block:: console

    $ manila-data \
        --config-file /etc/manila/manila.conf & \
        echo $! >opt/stack/status/stack/m-dat.pid; \
        fg || echo "m-dat failed to start" | \
        tee "/opt/stack/status/stack/m-dat.failure"


Creation of pilot share
-----------------------

In this step we assume that the following services are running:

- keystone
- nova (used by Generic driver, not strict dependency of manila)
- neutron (default network backend for Generic driver, used when driver handles share servers)
- cinder (used by Generic driver)

To operate a driver that handles share servers, we must create
a `share network`, which is a set of network information that will be used
during share server creation.
In our example, to use neutron, we will do the following:

.. code-block:: console

    $ neutron net-list

Here we note the ID of a neutron network and one of its subnets.

.. note::
    Some configurations of the Generic driver may require this network be
    attached to a public router. It is so by default. So, if you use the
    default configuration of Generic driver, make sure the network is attached
    to a public router.

Then define a share network using the neutron network and subnet IDs:

.. code-block:: console

    $ manila share-network-create \
        --name test_share_network \
        --neutron-net-id %id_of_neutron_network% \
        --neutron-subnet-id %id_of_network_subnet%

Now we can create a share using the following command:

.. code-block:: console

    $ manila create NFS 1 --name testshare --share-network test_share_network

The above command will instruct manila to schedule a share for creation. Once
created, configure user access to the new share before attempting to mount it
via the network:

.. code-block:: console

    $ manila access-allow testshare ip 0.0.0.0/0 --access-level rw

We added read-write access to all IP addresses. Now, you can try mounting this
NFS share onto any host. To determine the path required to mount the share onto
a host, run:

.. code-block:: console

    # manila share-export-location-list testshare
    +--------------------------------------+--------------------------------------------------------+-----------+
    | ID                                   | Path                                                   | Preferred |
    +--------------------------------------+--------------------------------------------------------+-----------+
    | 6921e862-88bc-49a5-a2df-efeed9acd583 | 10.0.0.3:/share-e1c2d35e-fe67-4028-ad7a-45f668732b1d   | False     |
    | b6bd76ce-12a2-42a9-a30a-8a43b503867d | 10.254.0.3:/share-e1c2d35e-fe67-4028-ad7a-45f668732b1d | False     |
    +--------------------------------------+--------------------------------------------------------+-----------+
