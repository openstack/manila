#!/bin/bash

MANILA_DIR='manila/' # include trailing slash
DOCS_DIR='source'

modules=''
for x in `find ${MANILA_DIR} -name '*.py' | grep -v manila/tests`; do
    if [ `basename ${x} .py` == "__init__" ] ; then
        continue
    fi
    relative=manila.`echo ${x} | sed -e 's$^'${MANILA_DIR}'$$' -e 's/.py$//' -e 's$/$.$g'`
    modules="${modules} ${relative}"
done

for mod in ${modules} ; do
  if [ ! -f "${DOCS_DIR}/${mod}.rst" ];
  then
    echo ${mod}
  fi
done
