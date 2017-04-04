#!/bin/bash
set -e
SCRIPT_DIR=$(dirname `readlink -f $0`)
$SCRIPT_DIR/manage.py test --noinput --settings=atmosphere.settings -v2 -- $@
