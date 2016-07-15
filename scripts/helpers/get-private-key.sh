#!/bin/bash

START_POS=$(awk -v a="$(cat ${1})" -v b="-----BEGIN ENCRYPTED PRIVATE KEY-----" 'BEGIN{print index(a,b)}')
PRIVATE_KEY_SZ=415

BEGIN=$(expr ${START_POS} + 4)
END=$(expr ${BEGIN} + ${PRIVATE_KEY_SZ})

cat "${1}" | cut -c${BEGIN}-${END} | sed 's/\\n/\'$'\n/g'