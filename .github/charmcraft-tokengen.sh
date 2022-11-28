#!/bin/bash
# Generate a Charmcraft token to use in the CI pipeline
# The token will be outputted to the file 'charmcraft_token'
# It should be added as a GitHub secret under the name 'CHARMCRAFT_AUTH'
charmcraft login --export=charmcraft_token \
  --charm=juju-qa-controller \
  --permission=package-manage-releases \
  --permission=package-manage-revisions \
  --permission=package-view \
  --ttl 3155760000
