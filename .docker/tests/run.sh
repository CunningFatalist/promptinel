#!/bin/bash

for file in .docker/tests/suites/*_tests.sh; do
  echo ""
  bash $file
done
