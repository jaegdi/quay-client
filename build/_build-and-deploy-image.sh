#!/usr/bin/env bash
set -o pipefail

scriptdir=$(dirname "$0")
dir="$(dirname "$scriptdir")"
cd "$dir" || exit 1
echo "Dir: $dir"
servicename="$1"
imagetag="$2"
# set cluster the the third parameter if given or to the env-Var CLUSTER
cluster="${3:-$CLUSTER}"
if [ "$cluster" != "$CLUSTER" ]; then
    # log into the cluster with a shell function, can be replaced with "oc login ....."
    source ocl "$cluster" -d
fi
echo "CLUSTER: $CLUSTER"
# unset my shell functio for podman, to use the native podman
unset podman
quayurl="registry-quay-quay.apps.pro-scp1.sf-rz.de"
image="$quayurl/scp/$servicename:$imagetag"

# when go build and podman build are ok, then go on
if echo && echo "### start go build" \
  && go mod tidy \
  && go build -v -o dist cmd/qc/main.go \
  && echo "### go build ready" \
  && echo \
  && echo "### start image build" \
  && podman build -f Dockerfile -t "$image"; then

    echo "# push the image to the quay registry"
    podman push "$image"
    echo "# pushed the image to the quay registry"

    # loop over the stages of our clusters
    for dst in $(cluster_list -all); do
        stage="${dst/-scp0/}"
        # log into the cluster
        if [ "$dst" == "pro-scp1" ]; then
            . ocl "$dst" "scp-ops-central" -d
        else
            . ocl "$dst" "scp-operations-$stage" -d
        fi
        # delete and deploy
        oc delete -f "deploy/deploy-$dst-$servicename.yml" --ignore-not-found
        if perl -lpe "s,\^(\s+image:)\s.+?/$servicename:latest\$,\$1 $image," < "deploy/deploy-$dst-$servicename.yml" | oc apply -f-; then
            echo "Deployed to $dst"
        else
            echo "Deploy failed to $dst"
            exit 1
        fi
        echo '-----------------------------------------------------------------------'
    done
    # log into the build cluster
    . ocl cid-scp0 scp-operations-cid
else
    echo "Build failed"
    exit 1
fi
