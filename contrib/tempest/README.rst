====================
Tempest Integration
====================

This directory contains the files necessary for tempest to cover Manila project.

To install:

  $ TEMPEST_DIR=<path to tempest>
  $ TEMPEST_COMMIT=<Commit-ID in `pre_test_hook.sh`>
  $ cd ${TEMPEST_DIR}
  $ git checkout ${TEMPEST_COMMIT}
  $ cd -
  $ cp -r tempest ${TEMPEST_DIR}

Notes
-----

These are pluggable-like files to Tempest project without requirement to change core Tempest files. But, due to constant changes of Tempest and absence of sync it can become incompatible with some states of Tempest. So, please look at file `contrib/ci/pre_test_hook.sh` where you can find commit that is used as HEAD of Tempest master branch.

