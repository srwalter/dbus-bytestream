#!/bin/bash

set -x
set -e

cargo build --verbose

cleanup() {
    kill $DBUS_SESSION_BUS_PID
}
trap cleanup EXIT
export $(dbus-launch --config-file ./test/test.conf)

export DBUS_TCP_BUS_ADDRESS=$(echo $DBUS_SESSION_BUS_ADDRESS | cut -d ';' -f 2)
export DBUS_SESSION_BUS_ADDRESS=$(echo $DBUS_SESSION_BUS_ADDRESS | cut -d ';' -f 1)
export DBUS_SYSTEM_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS
cargo test --verbose
