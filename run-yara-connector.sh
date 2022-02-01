#!/bin/bash
LABEL=edryaraconnector
IMAGE=yaraconnector/centos7:latest
EDR_MODULE_STORE=/var/cb/data/modulestore
CONFIG_SOURCE_DIR=/etc/cb/integrations/cb-yara-connector
LOG_DIR=/var/cb/integrations/cb-yara-connector
DATA_DIR=/var/cb/data/cb-yara-connector
MOUNT_POINTS="--mount type=bind,source=$CONFIG_SOURCE_DIR,target=/etc/cb/integrations/cb-yara-connector --mount type=bind,source=$DATA_DIR,target=$DATA_DIR --mount type=bind,source=$LOG_DIR,target=$LOG_DIR --mount type=bind,source=$EDR_MODULE_STORE,target=$EDR_MODULE_STORE" 
SERVICE_START='systemctl start cb-yara-connector'
SERVICE_STOP='systemctl stop cb-yara-connector'
SERVICE_RESTART='systemctl restart cb-yara-connector'
STARTUP_COMMAND="docker run --rm $MOUNT_POINTS --name $LABEL $IMAGE $SERVICE_START"
echo $STARTUP_COMMAND
SHUTDOWN_COMMAND="docker stop $LABEL" 
START_COMMAND="docker exec $LABEL $SERVICE_START"
RESTART_COMMAND="docker exec $LABEL $SERVICE_RESTART"
STOP_COMMAND="docker exec $LABEL $SERVICE_STOP"

print_help() {
  echo "Usage: edr-yara-connector-run COMMAND [options]"
  echo
  echo "Options:"
  echo "  -h, --help             Print this help message."
  echo
  echo "COMMANDs:"
  echo "  startup        Start the connector container"
  echo "  shutdown       Stop the connector container"
  echo "  start          Start the connector service"
  echo "  stop           Stop the connector service"
  echo "  restart        Restart the connector service"
  exit 2
}

PARSED=$(getopt -n run -o o: --long osversion:,help -- "$@")

if [ "${?}" != "0" ]; then
  print_help
fi

if [[ "${1}" == "" ]]; then
  echo "COMMAND required"; print_help
fi

if [[ "${1^^}" =~ ^(STARTUP|SHUTDOWN|START|STOP|RESTART)$ ]]; then
  echo "EDR Yara Connector: running ${1}..."
  case "${1^^}" in
    STARTUP) $STARTUP_COMMAND ;;
    SHUTDOWN) $SHUTDOWN_COMMAND ;;
  esac
else
  echo "run: invalid command '${1}'"; print_help
fi
