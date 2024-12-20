#!/bin/bash


echo "Build linux binary of qc (print columns)"
./build.sh qc
./qc -man > qc-ReadMe.md 2>/dev/null

echo "Build windows binary of qc"
GOOS=windows GOARCH=amd64 ./build.sh qc.exe

echo "generate ReadMe.md"
./qc -h > ReadMe.md

openshiftversion="$( oc version|grep Server|perl -lpe 's/^Server Version: (\d+\.\d+)\.\d+$/$1/')"

echo "Push to artifactory"
artifactory-upload.sh  -lf=qc             -tr=scptools-bin-develop   -tf=tools/qc
artifactory-upload.sh  -lf=qc             -tr=scptools-bin-develop   -tf="ocp-stable-${openshiftversion}/clients/qc"

artifactory-upload.sh  -lf=qc.exe         -tr=scptools-bin-develop   -tf=tools/qc
artifactory-upload.sh  -lf=qc.exe         -tr=scptools-bin-develop   -tf="ocp-stable-${openshiftversion}/clients/qc"

artifactory-upload.sh  -lf=qc-ReadMe.md   -tr=scptools-bin-develop   -tf=tools/qc

echo "Copy it to share folder PEWI4124://Daten"
cp qc qc.exe  /gast-drive-d/Daten/
cp qc-ReadMe.md  /gast-drive-d/Daten/
