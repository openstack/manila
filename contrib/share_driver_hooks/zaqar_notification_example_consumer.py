#!/usr/bin/env python
#
# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import print_function

import os
import pprint
import signal
import sys
import time

import netaddr
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_utils import timeutils
import six

opts = [
    cfg.IntOpt(
        "consume_interval",
        default=5,
        deprecated_name="sleep_between_consume_attempts",
        help=("Time that script will sleep between requests for consuming "
              "Zaqar messages in seconds."),
    ),
    cfg.StrOpt(
        "mount_dir",
        default="/tmp",
        help="Directory that will contain all mounted shares."
    ),
    cfg.ListOpt(
        "expected_ip_addresses",
        default=[],
        help=("List of IP addresses that are expected to be found in access "
              "rules to trigger [un]mount operation for a share.")
    ),
]

CONF = cfg.CONF


def print_with_time(data):
    time = six.text_type(timeutils.utcnow())
    print(time + " " + six.text_type(data))


def print_pretty_dict(d):
    pprint.pprint(d)


def pop_zaqar_messages(client, queues_names):
    if not isinstance(queues_names, (list, set, tuple)):
        queues_names = (queues_names, )
    try:
        user = client.conf['auth_opts']['options']['os_username']
        project = client.conf['auth_opts']['options']['os_project_name']
        messages = []
        for queue_name in queues_names:
            queue = client.queue(queue_name)
            messages.extend([six.text_type(m.body) for m in queue.pop()])
            print_with_time(
                "Received %(len)s message[s] from '%(q)s' "
                "queue using '%(u)s' user and '%(p)s' project." % {
                    'len': len(messages),
                    'q': queue_name,
                    'u': user,
                    'p': project,
                }
            )
        return messages
    except Exception as e:
        print_with_time("Caught exception - %s" % e)
        return []


def signal_handler(signal, frame):
    print("")
    print_with_time("Ctrl+C was pressed. Shutting down consumer.")
    sys.exit(0)


def parse_str_to_dict(string):
    if not isinstance(string, six.string_types):
        return string
    result = eval(string)
    return result


def handle_message(data):
    """Handles consumed message.

    Expected structure of a message is following:
        {'data': {
             'access_id': u'b28268b9-36c6-40d3-a485-22534077328f',
             'access_instance_id': u'd137b2cb-f549-4141-9dd7-36b2789fb973',
             'access_level': u'rw',
             'access_state': u'active',
             'access_to': u'7.7.7.7',
             'access_type': u'ip',
             'availability_zone': u'nova',
             'export_locations': [u'127.0.0.1:/path/to/nfs/share'],
             'is_allow_operation': True,
             'share_id': u'053eae9a-726f-4f7e-8502-49d7b1adf290',
             'share_instance_id': u'dc33e554-e0b9-40f5-9046-c198716d73a0',
             'share_proto': u'NFS'
        }}
    """
    if 'data' in data.keys():
        data = data['data']
    if (data.get('access_type', '?').lower() == 'ip' and
            'access_state' in data.keys() and
            'error' not in data.get('access_state', '?').lower() and
            data.get('share_proto', '?').lower() == 'nfs'):
        is_allow_operation = data['is_allow_operation']
        export_location = data['export_locations'][0]
        if is_allow_operation:
            mount_share(export_location, data['access_to'])
        else:
            unmount_share(export_location, data['access_to'])
    else:
        print_with_time('Do nothing with above message.')


def execute(cmd):
    try:
        print_with_time('Executing following command: \n%s' % cmd)
        cmd = cmd.split()
        stdout, stderr = processutils.execute(*cmd)
        if stderr:
            print_with_time('Got error: %s' % stderr)
        return stdout, stderr
    except Exception as e:
        print_with_time('Got following error: %s' % e)
        return False, True


def is_share_mounted(mount_point):
    mounts, stderr = execute('mount')
    return mount_point in mounts


def rule_affects_me(ip_or_cidr):
    if '/' in ip_or_cidr:
        net = netaddr.IPNetwork(ip_or_cidr)
        for my_ip in CONF.zaqar.expected_ip_addresses:
            if netaddr.IPAddress(my_ip) in net:
                return True
    else:
        for my_ip in CONF.zaqar.expected_ip_addresses:
            if my_ip == ip_or_cidr:
                return True
    return False


def mount_share(export_location, access_to):
    data = {
        'mount_point': os.path.join(CONF.zaqar.mount_dir,
                                    export_location.split('/')[-1]),
        'export_location': export_location,
    }
    if (rule_affects_me(access_to) and
            not is_share_mounted(data['mount_point'])):
        print_with_time(
            "Mounting '%(export_location)s' share to %(mount_point)s.")
        execute('sudo mkdir -p %(mount_point)s' % data)
        stdout, stderr = execute(
            'sudo mount.nfs %(export_location)s %(mount_point)s' % data)
        if stderr:
            print_with_time("Mount operation failed.")
        else:
            print_with_time("Mount operation went OK.")


def unmount_share(export_location, access_to):
    if rule_affects_me(access_to) and is_share_mounted(export_location):
        print_with_time("Unmounting '%(export_location)s' share.")
        stdout, stderr = execute('sudo umount %s' % export_location)
        if stderr:
            print_with_time("Unmount operation failed.")
        else:
            print_with_time("Unmount operation went OK.")


def main():
    # Register other local modules
    cur = os.path.dirname(__file__)
    pathtest = os.path.join(cur)
    sys.path.append(pathtest)

    # Init configuration
    CONF(sys.argv[1:], project="manila_notifier", version=1.0)
    CONF.register_opts(opts, group="zaqar")

    # Import common config and Zaqar client
    import zaqarclientwrapper

    # Handle SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # Run consumer
    print_with_time("Consumer was successfully run.")
    while(True):
        messages = pop_zaqar_messages(
            zaqarclientwrapper.ZAQARCLIENT, CONF.zaqar.zaqar_queues)
        if not messages:
            message = ("No new messages in '%s' queue[s] "
                       "found." % ','.join(CONF.zaqar.zaqar_queues))
        else:
            message = "Got following messages:"
        print_with_time(message)
        for message in messages:
            message = parse_str_to_dict(message)
            print_pretty_dict(message)
            handle_message(message)
        time.sleep(CONF.zaqar.consume_interval)


if __name__ == '__main__':
    main()
