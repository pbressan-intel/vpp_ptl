#!/usr/bin/bash -e

# EXIT ON ERROR
set -e -o pipefail

# DISPLAY HELP
Help()
{
   echo
   echo "SCRIPT HELP"
   echo
   echo "Usage: bash $0 [OPTIONS]"
   echo
   echo "*** OPTIONS ***"
   echo "<empty>                            Print this Help."
   echo "-b                                 Build."
   echo "-r                                 Run with network namespaces."
   echo
}

build_vpp()
{
  echo ">>>>> Building vpp <<<<<"
  echo
  pushd $REPO_DIR
  /usr/bin/make build
  popd
}

update_vpp_config()
{
  echo ">>>>> Updating vpp config <<<<<"
  echo
  /usr/bin/sed '/@VPP_NETNS_SETUP@/c\  startup-config '$CONFIGS_DIR/l4fw_vpp_setup'' $CONFIGS_DIR/vpp.conf_template > $CONFIGS_DIR/vpp.conf
}

reset_namespaces()
{
  echo ">>>>> Resetting network namespaces <<<<<"
  echo
  set +e
  /usr/bin/bash $SCRIPTS_DIR/cleanup_netns.sh
  set -e
  /usr/bin/bash $SCRIPTS_DIR/setup_netns.sh
}

run_vpp()
{
  echo ">>>>> Running vpp <<<<<"
  echo
  pushd $REPO_DIR
  STARTUP_CONF=$CONFIGS_DIR/vpp.conf /usr/bin/make run
}

# PROCESS ARGUMENTS
ProcArgs()
{
  case $1 in
   -b) # Build
       build_vpp
       update_vpp_config
       exit;;
   -r) # Run
       reset_namespaces
       run_vpp
       exit;;
    *) # Invalid option
       Help
       exit;;
  esac
}

# MAIN
SCRIPTS_DIR=$(cd `dirname $0` && pwd)
CONFIGS_DIR=$SCRIPTS_DIR/../configs
REPO_DIR=$SCRIPTS_DIR/../../..
VPP_PLUG=$REPO_DIR/src/plugins
OPT=$1
ProcArgs "$OPT"