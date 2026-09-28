#!/bin/sh
set -eu
exec /sbin/pfctl -a com.openduck -F all
