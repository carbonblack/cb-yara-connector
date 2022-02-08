#!/bin/bash
systemctl start cb-yara-connector
PID=$(cat /var/run/cb/integrations/cb-yara-connector.pid)
while [ -e /proc/$PID ]
do
    echo "Process: $PID is still running" >> /dev/null
done
