#!/bin/bash
output=${1:-qc}
main=${2:-cmd/qc/main.go}

echo
echo "---------------------------------------------------------------------------------"
echo "Tidy everything up"
go mod tidy
echo
echo "---------------------------------------------------------------------------------"
echo "build linux version (i assume you start the script on a linux machine)"
GOOS=linux GOARCH=amd64 go build -v -o $output $main
echo
echo "---------------------------------------------------------------------------------"
echo "build the windows version"
GOOS=windows GOARCH=amd64 go build -v -o ${output}.exe $main
echo
echo "finished"
ls -l qc*

if ./qc -h > /dev/null; then
    echo "Push to artifactory"

    artifactory-upload.sh -lf=qc       -tr=scptools-bin-dev-local   -tf=/tools/quay-client/quay-client-linux/
    artifactory-upload.sh -lf=qc       -tr=scpas-bin-dev-local      -tf=/istag_and_image_management/quay-client-linux/

    artifactory-upload.sh -lf=qc.exe   -tr=scptools-bin-dev-local   -tf=/tools/quay-client/quay-client-windows/
    artifactory-upload.sh -lf=qc.exe   -tr=scpas-bin-dev-local      -tf=/istag_and_image_management/quay-client-windows/

    # jf rt u --server-id default --flat qc  /scptools-bin-develop/tools/quay-client/quay-client-linux/qc
    # jf rt u --server-id default --flat qc  /scpas-bin-develop/istag_and_image_management/quay-client-linux/qc
    # jf rt u --server-id default --flat qc.exe  /scptools-bin-develop/tools/quay-client/quay-client-windows/qc.exe
    # jf rt u --server-id default --flat qc.exe  /scpas-bin-develop/istag_and_image_management/quay-client-windows/qc.exe

    echo "Copy it to share folder PEWI4124://Daten"
    cp qc qc.exe  /gast-drive-d/Daten/
fi