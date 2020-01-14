# Installing YARA Agent (Centos/RHEL 7+)

[YARA](https://virustotal.github.io/yara/) Integration is made up of two parts -- a master and one or more workers. The master service must be installed on the same system as CB EDR, while workers are usually installed on other systems (but can also be on the master system, if so desired). The YARA connector itself uses [Celery](http://www.celeryproject.org/) to distribute work to and remote (or local) workers - you will need to install and configure a [broker](https://docs.celeryproject.org/en/latest/getting-started/brokers/) (e.g., [Redis](https://redis.io/)) that is accessible to both the task-master and the remote worker instance(s).

The connector reads YARA rules from a configured directory to efficiently scan binaries as they are seen by the CB EDR server. The generated threat information is used to produce an intelligence feed for ingest by the CB EDR Server.

1. Download the latest RPM from the [GitHub releases page](https://github.com/carbonblack/cb-yara-connector/releases/download/untagged-b39ed959488c9ec78055/python-cb-yara-connector-2.1-0.x86_64.rpm).
1. Install the RPM:

    `yum install python-cb-yara-connector-<Latest>.rpm`

1. Enable the service:

    `systemctl enable cb-yara-connector`

# Create YARA Connector Config

The installation process creates a sample configuration file: `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.sample`.  Copy
this sample template to `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf`,
which is the filename and location that the connector expects.  You will likely have to edit this
configuration file on each system (master and workers) to supply any missing
information:
* There are two operating modes to support the two roles: `mode=master` and `mode=worker`. Both modes require a broker for Celery communications. Worker systems will need to change the mode to `worker`; if you plan to use the master system to also run a worker (not suggested, but allowed), the mode must be `master+worker`.
* Remote worker systems will require the master's URL for `cb_server_url` (local workers need no modification);
 they also require  the token of a global admin user for `cb_server_token`. 
* Remote workers will require the URL of the master's Redis server 

The daemon will attempt to load the PostgreSQL credentials from the CB EDR server's `cb.conf` file, 
if available, falling back to the PostgreSQL connection information in the master's configuration file using the `postgres_xxxx` keys in the config. The REST API location and credentials are specified in the `cb_server_url` and `cb_server_token` keys, respectively. 

```ini
;
; Cb Response PostgreSQL Database settings, required for 'master' and 'master+worker' systems
; The seever will attempt to read from local cb.conf file first and fall back
; to these settings if it cannot do so.
;
postgres_host=127.0.0.1
postgres_username=cb
postgres_password=<POSTGRES PASSWORD GOES HERE>
postgres_db=cb
postgres_port=5002
```

```ini
;
; Cb EDR server settings, required for 'worker' and 'master+worker' systems
; For remote workers, the cb_server_url mus be that of the master
;
cb_server_url=https://127.0.0.1
cb_server_token=<API TOKEN GOES HERE>
```

You must configure `broker=` which sets the broker and results_backend for Celery. 
Set this appropriately as per the [Celery documentation](https://docs.celeryproject.org/en/latest/getting-started/brokers/).

```ini
;
; URL of the Redis server, defaulting to the local CB EDR server Redis for the master.  If this is a worker
; system, alter to point to the master system.  If you are using a standalone Redis server, both master and
; workers must point to the same server.
;
broker_url=redis://127.0.0.1
```
## Create your YARA rules

The YARA connector monitors the directory `/etc/cb/integrations/cb-yara-connector/yara_rules` for files (`.yar`) each 
specifying one or more YARA rule. Your rules must have `meta` section with a 
`score = [1-10]` tag to appropriately score matching binaries.  This directory is 
configurable in your configuration file. C-style comments are supported.

###### Sample YARA Rule File
```
// Sample rule to match binaries over 100kb in size

rule matchover100kb {
	meta:
		score = 10
	condition:
		filesize > 100KB
}
```

#### Controlling the YARA Agent 

| Action | Command |
| ------ | ------- |
| Start the service | `systemctl start cb-yara-connector` |
| Stop the service | `systemctl stop cb-yara-connector` |
| Display logging information | `systemctl status -l cb-yara-connector` | 
| Displaying verbose logs | `journalctl -u cb-YARA-connector.service` |

# Development Notes	

## Utility Script
Included with this version is a feature for discretionary use by advanced users and
should be used with caution.

When `utility_interval` is defined with a value greater than 0, it represents the interval
in minutes at which the YARA connector will pause its work and execute an external
shell script.  A sample script, `vacuumscript.sh`  is provided within the `scripts` folder
of the current YARA connector installation. After execution, the YARA connector continues with
its work.

> _**NOTE:** As a safety for this feature, if an interval is defined but no script is defined, nothing is done.
> By default, no script is defined._

```ini
;
; The use of the utility script is an ADVANCED FEATURE and should be used with caution!
;
; If "utility_interval" is greater than 0 it represents the interval in minutes after which the YARA connector will
; pause to execute a shell script for general maintenance. This can present risks. Be careful what you allow the
; script to do, and use this option at your own discretion.
;
utility_interval=-1
utility_script=./scripts/vacuumscript.sh
```

## YARA Agent Build Instructions 

The dockerfile in the top-level of the repo contains a CentOS 7 environment for running, building, and testing 
the connector. 

The provided script `docker-build-rpm.sh` will use docker to build the project, and place the RPM(s) in `${PWD}/RPMS`. 


##### Command-line Options
```text
usage: main.py [-h] --config-file CONFIG_FILE [--log-file LOG_FILE]
               [--output-file OUTPUT_FILE] [--validate-yara-rules] [--debug]

YARA Agent for YARA Connector

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        Location of the config file
  --log-file LOG_FILE   Log file output (defaults to `local` folder)
  --output-file OUTPUT_FILE
                        output feed file (defaults to `local` folder)
  --validate-yara-rules
                        ONLY validate YARA rules in a specified directory
  --debug               Provide additional logging

```
###### --config-file
Provides the path of the configuration file to be used _**(REQUIRED)**_

###### --log-file
Provides the path of the YARA log file.  If not supplied, defaults to `local/yara_agent.log`
within the current YARA package.

###### --output-file
Provides the path containing the feed description file.  If not supplied, defaults to
`feed.json` in the same location as the configured `feed_database_dir` folder.

###### --validate-yara-rules
If supplied, YARA rules will be validated and the script will exit.

#### Example Cron Entry
_[TBD]_

---
# Dev install 

Use Git to retrieve the project, create a new virtual environment using Python 3.6+, and use pip to install the requirements:

```
git clone https://github.com/carbonblack/cb-yara-connector
pip3 install -r requirements.txt
```
