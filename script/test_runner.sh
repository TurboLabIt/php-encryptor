#!/usr/bin/env bash
SCRIPT_NAME=test_runner

XDEBUG_MODE=off ${PHP_CLI} ./vendor/bin/phpunit tests

echo ""
