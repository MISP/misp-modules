#!/bin/sh

# If no contain is there or curl get an error back: exit 1. Docker restart then the container.
curl -fk http://0.0.0.0:6666/modules || exit 1