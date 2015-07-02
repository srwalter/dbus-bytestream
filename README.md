# dbus-bytestream

[![Build Status](https://travis-ci.org/srwalter/dbus-bytestream.svg?branch=master)](https://travis-ci.org/srwalter/dbus-bytestream)

Rust-native implementation of the D-Bus wire protocol.  Supports TCP and
UNIX socket transports, as well as EXTERNAL, COOKIE and ANONYMOUS
authentication.  Uses dbus-serialize for the client facing D-Bus types.
