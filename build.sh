#!/bin/bash
output=${1:-qc}

go mod tidy
go build -v -o $output cmd/qc/main.go
