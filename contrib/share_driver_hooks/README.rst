Manila mount automation example using share driver hooks feature
================================================================

Manila has feature called 'share driver hooks'. Which allows to perform
actions before and after driver actions such as 'create share' or
'access allow', also allows to do custom things on periodic basis.

Here, we provide example of mount automation using this feature.
This example uses OpenStack Zaqar project for sending notifications
when operations 'access allow' and 'access deny' are performed.
Server side hook will send notifications about changed access for shares
after granting and prior to denying access.


Possibilities of the mount automation example (consumer)
--------------------------------------------------------

- Supports only 'NFS' protocol.
- Supports only 'IP' rules.
- Supports both levels of access - 'RW' and 'RO'.
- Consume interval can be configured.
- Allows to choose parent mount directory.


Server side setup and run
-------------------------

1. Place files 'zaqarclientwrapper.py' and 'zaqar_notification.py' to dir
%manila_dir%/manila/share/hooks.

Then update manila configuration file with following options:

::

    [share_backend_config_group]
    hook_drivers = manila.share.hooks.zaqar_notification.ZaqarNotification
    enable_pre_hooks = True
    enable_post_hooks = True
    enable_periodic_hooks = False

    [zaqar]
    zaqar_auth_url = http://%ip_of_endpoint_with_keystone%:35357/v2.0/
    zaqar_region_name = %name_of_region_optional%
    zaqar_username = foo_user
    zaqar_password = foo_tenant
    zaqar_project_name = foo_password
    zaqar_queues = manila_notification

2. Restart manila-share service.


Consumer side setup and run
---------------------------

1. Place files 'zaqarclientwrapper.py' and
'zaqar_notification_example_consumer.py' to any dir on user machine, but they
both should be in the same dir.

2. Make sure that following dependencies are installed:

- PIP dependencies:

  - netaddr

  - oslo_concurrency

  - oslo_config

  - oslo_utils

  - python-zaqarclient

  - six

- System libs that install 'mount' and 'mount.nfs' apps.

3. Create file with following options:

::

    [zaqar]
    # Consumer-related options
    sleep_between_consume_attempts = 7
    mount_dir = "/tmp"
    expected_ip_addresses = 10.254.0.4

    # Common options for consumer and server sides
    zaqar_auth_url = http://%ip_of_endpoint_with_keystone%:35357/v2.0/
    zaqar_region_name = %name_of_region_optional%
    zaqar_username = foo_user
    zaqar_password = foo_tenant
    zaqar_project_name = foo_password
    zaqar_queues = manila_notification

Consumer options descriptions:

- 'sleep_between_consume_attempts' - wait interval between consuming
  notifications from message queue.

- 'mount_dir' - parent mount directory that will contain all mounted shares
  as subdirectories.

- 'expected_ip_addresses' - list of IP addresses that are expected
  to be granted access for. Could be either equal to or be part of a CIDR.
  Match triggers [un]mount operations.

4. Run consumer with following command:

::

    $ zaqar_notification_example_consumer.py --config-file path/to/config.conf

5. Now create NFS share and grant IP access to consumer by its IP address.
