#!/bin/bash
go mod tidy
go build -v -o qc cmd/qc/main.go
