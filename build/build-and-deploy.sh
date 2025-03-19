#!/usr/bin/env bash
set -eo pipefail

. ocl cid-scp0 >/dev/null 2>&1

script="$(basename "$0")"
scriptdir="$(dirname "$0")"
dir=$(dirname "$scriptdir")
echo "script: $script, scriptdir: $scriptdir, Dir: $dir"
cd "$dir"

# set this variable to correct values
CLUSTER=cid-scp0
quayurl="registry-quay-quay.apps.pro-scp1.sf-rz.de"     # default='registry-quay-quay.apps.pro-scp1.sf-rz.de'
build='qc'                             # name of the go binary
build_service_image='false'            # name of the image-stream, if a service image should be created, default='false'. If not false, you need a Dockerfile in repo root.
tagversion="latest"
# end var

if podman login -u "$USER" -p "$(eval "$LDAPPASSWORDPROVIDER")" "$quayurl" >/dev/null 2>&1; then
    echo "quayurl: $quayurl"
else
    echo "ERROR: podman login failed" 1>&2
    exit 1
fi


hilfe() {
    if [[ -n $1 ]]; then
        echo
        echo '***'  "$*"  '***'
        echo
    fi
    cat <<-EOH

    SYNOPSIS
        $script [-b|--build] [-h|--help]

    OPTIONS
        -b <name> | --build[=]<name>
            Enable to build the $build executable and deploy to artifactory. Default is '$build'
        -t <tag> | --tag[=]<tag>
            The tag version of the $build to build. Default is 'latest' tag, thats means the head in git repo.
            With '-t newest | --tag newest' the newest tag in git is used.
            If the tag is not lattest (default), the the git repo is checked out to the given tag for the build.
        -h | --help
            Print this help message

    DESCRIPTION
        $script builds and deploys the $build to the specified cluster.

    EXAMPLES
        $script [-b name] -t v1.0.0
            Build the $build with tag v1.0.0 and deploy it
        $script [-b name] -t newest
            Build the $build with the newest tag that is defined in git
        $script [-b name]
            Build the $build with the latest tag
EOH
}

echo "# evaluate params"
die() { echo "$*" >&2; exit 2; }  # complain to STDERR and exit with error
needs_arg() { if [ -z "$OPTARG" ]; then die "No arg for --$OPT option"; fi; }
optspec=":vhb:t:-:" # allow -b with arg, -t with arg, -v, -h, and -- "with arg"
while getopts $optspec OPT; do
  # support long options: https://stackoverflow.com/a/28466267/519360
  if [ "$OPT" = "-" ]; then   # long option: reformulate OPT and OPTARG
    OPT="${OPTARG%%=*}"       # extract long option name
    OPTARG="${OPTARG#"$OPT"}" # extract long option argument (may be empty)
    OPTARG="${OPTARG#=}"      # if long option argument, remove assigning `=`
  fi
  case "$OPT" in
    b | build )    needs_arg; build="$OPTARG" ;;
    t | tag   )    needs_arg; tagversion="$OPTARG" ;;
    h | help )     hilfe '';exit ;;  # optional argument
    \? )           hilfe 'bad short option'; exit 2 ;;      # bad short option (error reported via getopts)
    * )            hilfe "Illegal option --$OPT"; exit 2 ;; # bad long option
  esac
done
shift $((OPTIND-1))    # remove parsed options and args from $@ list

# ======================  M A I N  ======================

if [ "$tagversion" == 'newest' ]; then
    tagversion="$(get-git-tag.sh)"
    read -p "# Do you want to checkout the tag $tagversion? [y/N]" answer
    if [[ ! $answer =~ ^[Yy] ]]; then
        tagversion='latest'
        echo "# Then i build with git tag 'latest'"
    fi
fi
echo "# remember cluster"
remember-current-cluster

# login in the build cluster, which is cid-scp0, where the scp-build namespace is located
if ocl cid-scp0 -d > /dev/null 2>&1 &&
    ocl > /dev/null 2>&1; then  # login in the current cluster
    echo "# working on CLUSTER: $CLUSTER"
else
    echo "ERROR: ocl login failed" 1>&2
    exit 1
fi

echo "# B U I L D   L O C A L   A N D   D E P L O Y   T O   A R T I F A C T O R Y"
if [ "$build" != 'false' ]; then
    if [ "$tagversion" != 'latest' ]; then
        # Ensure git checkout master is executed on script exit
        trap 'git checkout master' EXIT
        echo "# git checkout $tagversion"
        git checkout "$tagversion"
    fi

    # build the $build and deploy to artifactory
    echo "# Build $build local and deploy to artifactory"
    if "$scriptdir"/_build-and-deploy-to-artifactory.sh $build; then
        echo "# Build and deploy to artifactory was successful"
    else
        echo "ERROR: Build and deploy to artifactory failed" 1>&2
    fi

    # build the $build image and deploy to artifactory
    if [ "$build_service_image" != 'false' ]; then
        echo "###### B u i l d    i m a g e   $build_service_image   w i t h   $tagversion   ########"
        echo "$scriptdir"/_build-and-deploy-image.sh $build_service_image $tagversion
        if "$scriptdir"/_build-and-deploy-image.sh $build_service_image $tagversion; then
            echo "# Build and deploy service, deploy image to quay was successful"
        else
            echo "ERROR: Build and deploy service, deploy image to quay was failed" 1>&2
        fi
    fi

fi

switch-back-to-current-cluster
