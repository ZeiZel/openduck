#!/bin/sh
set -eu
# Deterministic synthetic benchmark: fixed iterations, no network/model fallback.
GOCACHE="${GOCACHE:-/tmp/openduck-go-cache}" go test ./internal/core -run '^$' -bench '^BenchmarkDLP$' -benchtime=1000x -count=1
printf '%s\n' 'model_benchmark=blocked: explicit model installation and approval required'
