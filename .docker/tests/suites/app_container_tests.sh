#!/bin/bash

source .docker/tests/functions.sh

DOCKER_COMPOSE_EXEC="docker compose exec -T promptinel_app"

describe "promptinel_app container"

should "have go installed"
${DOCKER_COMPOSE_EXEC} go version > /dev/null 2>&1 \
  && pass "go is installed" \
  || fail "go is not installed"

should "have curl installed"
${DOCKER_COMPOSE_EXEC} curl --version > /dev/null 2>&1 \
  && pass "curl is installed" \
  || fail "curl is not installed"

should "have git installed"
${DOCKER_COMPOSE_EXEC} git --version > /dev/null 2>&1 \
  && pass "git is installed" \
  || fail "git is not installed"

should "have golanglint-ci installed"
${DOCKER_COMPOSE_EXEC} golangci-lint --version > /dev/null 2>&1 \
  && pass "golanglint-ci is installed" \
  || fail "golanglint-ci is not installed"

should "have govulncheck installed"
${DOCKER_COMPOSE_EXEC} govulncheck --version > /dev/null 2>&1 \
  && pass "govulncheck is installed" \
  || fail "govulncheck is not installed"

should "have goreleaser installed"
${DOCKER_COMPOSE_EXEC} goreleaser --version > /dev/null 2>&1 \
  && pass "goreleaser is installed" \
  || fail "goreleaser is not installed"

finish
