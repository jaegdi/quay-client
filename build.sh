#!/bin/bash
go mod tidy
go build -o qc cmd/qc/main.go
