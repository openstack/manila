from __future__ import print_function

import gettext
import os

gettext.install('manila')

from manila import utils


def setup(app):
    print("**Autodocumenting from %s" % os.path.abspath(os.curdir))
    rv = utils.execute('./doc/generate_autodoc_index.sh')
    print(rv[0])
