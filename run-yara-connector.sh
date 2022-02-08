#!/bin/bash
LABEL=edryaraconnector
IMAGE=yaraconnector/centos7:latest
EDR_MODULE_STORE_EXTERNAL=/var/cb/data/modulestore
EDR_MODULE_STORE=/var/cb/data/modulestore
CONFIG_DIR_EXTERNAL=/etc/cb/integrations/cb-yara-connector
CONFIG_DIR=/etc/cb/integrations/cb-yara-connector
LOG_DIR_EXTERNAL=/var/log/cb/integrations/cb-yara-connector
LOG_DIR=/var/log/cb/integrations/cb-yara-connector
DATA_DIR_EXTERNAL=/var/cb/data/cb-yara-connector
DATA_DIR=/var/cb/data/cb-yara-connector
MOUNT_POINTS="--mount type=bind,source=$CONFIG_DIR_EXTERNAL,target=$CONFIG_DIR --mount type=bind,source=$DATA_DIR_EXTERNAL,target=$DATA_DIR --mount type=bind,source=$LOG_DIR_EXTERNAL,target=$LOG_DIR --mount type=bind,source=$EDR_MODULE_STORE_EXTERNAL,target=$EDR_MODULE_STORE"
STARTUP_COMMAND="docker run -d --rm $MOUNT_POINTS --name $LABEL $IMAGE"
STATUS_COMMAND=get_container_status

get_container_status () {
    CONTAINER_NAME=$(docker ps | grep $LABEL | head -n1 | awk '{print $1}')
    if [ "${#CONTAINER_NAME}" -gt 0 ]; then
        CONTAINER_RUNNING=true
        echo "EDR Yara Container status: Running"
        echo "EDR Yara Container identifier: ${CONTAINER_NAME}"
    else
        # run ps with -a switch to see if stopped or non-existent
        STOPPED_NAME=$(docker ps | grep $LABEL | head -n1 | awk '{print $1}')
        if [ "${#STOPPED_NAME}" -gt 0 ]; then
            echo "EDR Yara Container status: Stopped "
        else
            echo "EDR Yara Container status: No running container"
        fi
        CONTAINER_RUNNING=false
    fi
}

SHUTDOWN_COMMAND=stop_and_remove_container
stop_and_remove_container() {
    docker stop $LABEL > /dev/null
    docker rm $LABEL > /dev/null
}

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
