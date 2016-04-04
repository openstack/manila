#!/bin/bash

tree=$1

tmpfile=$(mktemp)

find $tree -name '*.py' \
    | xargs grep -l 'import log' \
    | xargs grep -l '^LOG =' \
    | xargs grep -c  'LOG' \
    | grep ':1$' \
    | awk -F ':' '{print $1}' > $tmpfile

count=$(wc -l < $tmpfile)

if [[ count -eq 0 ]]; then
    rm $tmpfile
    exit 0
fi

echo 'Found files with unused LOG variable (see https://review.openstack.org/#/c/301054):'
cat $tmpfile
rm $tmpfile
exit 1




