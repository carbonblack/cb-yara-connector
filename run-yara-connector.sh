#!/bin/bash
LABEL=edryaraconnector
IMAGE=yaraconnector/centos7:latest
EDR_MODULE_STORE=/var/cb/data/modulestore
CONFIG_DIR=/etc/cb/integrations/cb-yara-connector
LOG_DIR=/var/log/cb/integrations/cb-yara-connector
DATA_DIR=/var/cb/data/cb-yara-connector
MOUNT_POINTS="--mount type=bind,source=$CONFIG_DIR,target=$CONFIG_DIR --mount type=bind,source=$DATA_DIR,target=$DATA_DIR --mount type=bind,source=$LOG_DIR,target=$LOG_DIR --mount type=bind,source=$EDR_MODULE_STORE,target=$EDR_MODULE_STORE"
SERVICE_START='systemctl start cb-yara-connector'
CONTAINER_RUNNING=$(docker inspect --format="{{.State.Running}}" $LABEL 2> /dev/null)
if [ "$CONTAINER_RUNNING" == "true" ]; then
  STARTUP_COMMAND="echo EDR Yara Connector container already running"
  STATUS_COMMAND="docker exec $LABEL systemctl status cb-yara-connector"
else
  STARTUP_COMMAND="docker run -d --rm $MOUNT_POINTS --name $LABEL $IMAGE $SERVICE_START"
  STATUS_COMMAND="echo EDR Yara Connector container is stopped"
fi
SHUTDOWN_COMMAND="docker stop $LABEL"


print_help() {
  echo "Usage: edr-yara-connector-run COMMAND [options]"
  echo
  echo "Options:"
  echo "  -h, --help             Print this help message."
  echo
  echo "COMMANDs:"
  echo "  start        Start the connector"
  echo "  stop       Stop the connector"
  echo "  status         Stop the connector"
  exit 2
}

PARSED=$(getopt -n run -o o: --long osversion:,help -- "$@")

if [ "${?}" != "0" ]; then
  print_help
fi

if [[ "${1}" == "" ]]; then
  echo "COMMAND required"; print_help
fi

if [[ "${1^^}" =~ ^(START|STOP|STATUS)$ ]]; then
  echo "EDR Yara Connector: running ${1}..."
  case "${1^^}" in
    START) $STARTUP_COMMAND ;;
    STOP) $SHUTDOWN_COMMAND ;;
    STATUS) $STATUS_COMMAND ;;
  esac
else
  echo "run: invalid command '${1}'"; print_help
fi
