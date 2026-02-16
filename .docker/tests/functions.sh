#!/bin/bash

ERRORS=0
TESTS=0

describe() {
  echo -e "\033[1;34m$1\033[0m"
}

should() {
  TESTS=$((TESTS+1))
  echo -e "  \033[0;34mshould $1\033[0m"
}

fail() {
  echo -e "    \033[0;31m✘ $1\033[0m"
  ERRORS=$((ERRORS+1))
}

pass() {
  echo -e "    \033[0;32m✔ $1\033[0m"
}

finish () {
  if [ $ERRORS -gt 0 ]; then
    echo -e "\033[1;31m$ERRORS of $TESTS tests failed\033[0m"
    exit 1
  else
    echo -e "\033[1;32mall $TESTS tests passed\033[0m"
    exit 0
  fi
}
