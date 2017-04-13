#!/bin/bash
set -e
SCRIPT_DIR=$(dirname `readlink -f $0`)
$SCRIPT_DIR/manage.py test --noinput --settings=atmosphere.settings -v2 -- $@
#$SCRIPT_DIR/manage.py test --noinput --liveserver=localhost:8082 --settings=atmosphere.settings $SCRIPT_DIR/tests -- $@
