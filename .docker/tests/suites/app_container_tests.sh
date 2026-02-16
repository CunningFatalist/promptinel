#!/bin/bash

source .docker/tests/functions.sh

describe "promptinel_app container"

should "have go installed"
docker compose exec promptinel_app go version > /dev/null 2>&1 \
  && pass "go is installed" \
  || fail "go is not installed"

should "have curl installed"
docker compose exec promptinel_app curl --version > /dev/null 2>&1 \
  && pass "curl is installed" \
  || fail "curl is not installed"

should "have git installed"
docker compose exec promptinel_app git --version > /dev/null 2>&1 \
  && pass "git is installed" \
  || fail "git is not installed"

should "have golanglint-ci installed"
docker compose exec promptinel_app golangci-lint --version > /dev/null 2>&1 \
  && pass "git is installed" \
  || fail "git is not installed"

finish
