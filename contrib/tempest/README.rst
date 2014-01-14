====================
Tempest Integration
====================

This directory contains the files necessary for tempest to cover Manila project.

To install:

$ TEMPEST_DIR=/path/to/tempest

$ cp tempest/* ${TEMPEST_DIR}

notes:

These files based on tempest master branch (pre-icehouse), it is pluggable-like files without requirements to change core tempest files. But the way of its pluggability is work-around for tempest, which hasn't pluggable functionality for exceptions, config and clients modules.

