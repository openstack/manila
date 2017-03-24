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
from manila.i18n import _
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
        #
        # (aovchinnikov): To actually make docker container mount a
        # logical volume created after container start-up to some location
        # inside it, we must share entire /dev with it. While seemingly
        # dangerous it is not and moreover this is apparently the only sane
        # way to do it. The reason is when a logical volume gets created
        # several new things appear in /dev: a new /dev/dm-X and a symlink
        # in /dev/volume_group_name pointing to /dev/dm-X. But to be able
        # to interact with /dev/dm-X, it must be already present inside
        # the container's /dev i.e. it must have been -v shared during
        # container start-up. So we should either precreate an unknown
        # number of /dev/dm-Xs (one per LV), share them all and hope
        # for the best or share the entire /dev and hope for the best.
        #
        # The risk of allowing a container having access to entire host's
        # /dev is not as big as it seems: as long as actual share providers
        # are invulnerable this does not pose any extra risks. If, however,
        # share providers contain vulnerabilities then the driver does not
        # provide any more possibilities for an exploitation than other
        # first-party drivers.

        cmd = ["docker", "run", "-d", "-i", "-t", "--privileged",
               "-v", "/dev:/dev", "--name=%s" % name,
               "-v", "/tmp/shares:/shares", image_name]
        result = self._inner_execute(cmd) or ["", 1]
        if result[1] != "":
            raise exception.ManilaException(
                _("Container %s has failed to start.") % name)
        LOG.info("A container has been successfully started! Its id is "
                 "%s.", result[0].rstrip('\n'))

    def stop_container(self, name):
        LOG.debug("Stopping container %s.", name)
        cmd = ["docker", "stop", name]
        result = self._inner_execute(cmd) or ['', 1]
        if result[1] != '':
            raise exception.ManilaException(
                _("Container %s has failed to stop properly.") % name)
        LOG.info("Container %s is successfully stopped.", name)

    def execute(self, name=None, cmd=None):
        if name is None:
            raise exception.ManilaException(_("Container name not specified."))
        if cmd is None or (type(cmd) is not list):
            raise exception.ManilaException(_("Missing or malformed command."))
        LOG.debug("Executing inside a container %s.", name)
        cmd = ["docker", "exec", "-i", name] + cmd
        result = self._inner_execute(cmd)
        LOG.debug("Run result: %s.", result)
        return result

    def _inner_execute(self, cmd):
        LOG.debug("Executing command: %s.", " ".join(cmd))
        try:
            result = self._execute(*cmd, run_as_root=True)
        except Exception:
            LOG.exception("Executing command failed.")
            return None
        LOG.debug("Execution result: %s.", result)
        return result
