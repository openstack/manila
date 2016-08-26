# Copyright (c) 2016 Mirantis, Inc.
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

import uuid

from oslo_log import log

from manila import exception
from manila.i18n import _, _LI
from manila.share import driver


LOG = log.getLogger(__name__)


class DockerExecHelper(driver.ExecuteMixin):
    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        super(DockerExecHelper, self).__init__(*args, **kwargs)
        self.init_execute_mixin()

    def start_container(self, name=None):
        name = name or "".join(["manila_cifs_docker_container",
                                str(uuid.uuid1()).replace("-", "_")])
        image_name = self.configuration.container_image_name
        LOG.debug("Starting container from image %s.", image_name)
        # (aovchinnikov): --privileged is required for both samba and
        # nfs-ganesha to actually allow access to shared folders.
        cmd = ["docker", "run", "-d", "-i", "-t", "--privileged",
               "--name=%s" % name, '-v', "/tmp/shares:/shares", image_name]
        result = self._inner_execute(cmd) or ['', 1]
        if result[1] != '':
            raise exception.ManilaException(
                _("Container %s has failed to start.") % name)
        LOG.info(_LI("A container has been successfully started! Its id is "
                     "%s."), result[0].rstrip('\n'))

    def stop_container(self, name):
        LOG.debug("Stopping container %s.", name)
        cmd = ["docker", "stop", name]
        result = self._inner_execute(cmd) or ['', 1]
        if result[1] != '':
            raise exception.ManilaException(
                _("Container %s has failed to stop properly.") % name)
        LOG.info(_LI("Container %s is successfully stopped."), name)

    def execute(self, name=None, cmd=None):
        if name is None:
            raise exception.ManilaException(_("Container name not specified."))
        if cmd is None or (type(cmd) is not list):
            raise exception.ManilaException(_("Missing or malformed command."))
        LOG.debug("Executing inside a container %s.", name)
        cmd = ["docker", "exec", "-i", name] + cmd
        result = self._inner_execute(cmd)
        LOG.debug("Run result: %s.", str(result))
        return result

    def _inner_execute(self, cmd):
        LOG.debug("Executing command: %s.", " ".join(cmd))
        try:
            result = self._execute(*cmd, run_as_root=True)
        except Exception as e:
            LOG.exception(e)
            return None
        LOG.debug("Execution result: %s.", result)
        return result
