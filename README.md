# Installing Yara Agent (Centos/RHEL 7+)

The Yara Integration is made up of two parts -- a master and one or more workers.
The master service must be installed on the same system as Cb Response, while workers
are usually installed on other systems (but can also be on the master system, if so
desired). 

The yara connector itself uses celery to distribute work to and remote (or local) workers - you will need to install and 
configure a broker (ex, redis, postgres) that is accessible to both the task-master and the remote worker instance(s).

Download the latest RPM from the github releases page, [here](https://github.com/carbonblack/cb-yara-connector/releases/download/untagged-c64dc62eb602dc1b82df/python-cb-yara-connector-2.1-0.x86_64.rpm).

Once downloaded, the connector can be easily installed from the rpm:

`yum install python-cb-yara-connector-<Latest>.rpm` 

The connector uses a configured directory containing yara rules, to efficiently scan binaries as they
are seen by the CB Response Server. The generated threat information is used to produce an
intelligence feed for ingest by the Cb Response Server again.

# Create Yara Connector Config

The installation process will create a sample configuration file in the control directory
as `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.sample`.  Simply copy
this sample template to `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf`,
which is looked for by the yara connectory service.  You will likely have to edit this
configuration file on each system (master and workers) to supply any missing
information:
* worker systems will need to change the mode to `worker`; if you plan to use the master
system to also run a worker (not suggested, but allowed), the mode must be `master+worker`.
* Remote worker systems will require the master's URL for `cb_server_url` (local workers need no modification);
 they also require  the token of a global admin user for `cb_server_token`. 
* Remote workers will require the URL of the master's redis server 

The daemon will attempt to load the postgres credentals from the response server's `cb.conf`, 
if available, falling back to  postgres connection information for your CBR server 
in the master's configurration file using the `postgres_xxxx` keys in the config. The REST API location and credentials are specified in the `cb_server_url` and `cb_server_token` keys, respectively. 

```ini
;
; Cb Response postgres Database settings, required for 'master' and 'master+worker' systems
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
; Cb Response Server settings, required for 'worker' and 'master+worker' systems
; For remote workers, the cb_server_url mus be that of the master
;
cb_server_url=https://127.0.0.1
cb_server_token=<API TOKEN GOES HERE>
```

You must configure `broker=` which sets the broker and results_backend for celery. 
You will set this appropriately as per the celery documentation - 
here (https://docs.celeryproject.org/en/latest/getting-started/brokers/).

```ini
;
; URL of the redis server, defaulting to the local response server redis for the master.  If this is a worker
; system, alter to point to the master system.  If you are using a standalone redis server, both master and
; workers must point to the same server.
;
broker_url=redis://127.0.0.1
```

The yara-connector RPM contains a service that is primarily intended to serve as a distributed system, with a master serving work to remote worker machine(s) for analysis and compiling a threat intelligence feed for Carbon Black Response EDR.

There are two operating modes to support the two roles: `mode=master` and `mode=worker`.

Install the connector on the cbr server, and config it with the master mode - configure postgres credentials, and a directory of monitored yara rules. In worker mode, configure REST API credentials. Both modes require a broker for celery communications.

## Input your yara rules

The yara connector monitors the directory `/etc/cb/integrations/cb-yara-connector/yara_rules` for files (`.yar`) each 
specifying one or more yara rule. Your rules must have `meta` section with a 
`score = [1-10]` tag to appropriately score matching binaries.  This directory is 
configurable in your configuration file. C-style comments are supported.

###### Sample Yara Rule File
```
// Sample rule to match binaries over 100kb in size

rule matchover100kb {
	meta:
		score = 10
	condition:
		filesize > 100KB
}
```

#### Running Yara Agent 

`systemctl start cb-yara-connector` will up the service using systemD. 

`systemctl stop cb-yara-connector` will gracefully stop the yara-connector.

`systemctl status -l cb-yara-connector` will display logging information. 

#### Example Yara Connector Master configuration

```ini
[general]

;
; Python Celery Broker Url. Set this full url stringg
; Example: redis://<ip_address>
;
broker_url=redis://127.0.0.1

mode=master

;
; Cb Response Server Configuration
; Used for downloading binaries
;
cb_server_url=https://localhost
cb_server_token=12345678910

;
; Directory for temporary yara rules storage
; WARNING: Put your yara rules with the yara agent.  This is just temporary storage.
;
yara_rules_dir=/etc/cb/integrations/cb-yara-connector/yara-rules
```

### Example Remote Worker configuration

```ini
[general]

;
; Python Celery Broker Url. Set this full url stringg
; Example: redis://<ip_address>
;
broker_url=redis://master.server.url

mode=worker

;
; Cb Response Server Configuration
; Used for downloading binaries
;
cb_server_url=https://master.server.url
cb_server_token=12345678910

```

# Development Notes	

## Utility Script
Included with this version is a feature for discretionary use by advanced users and
should be used with caution.

When `utility_interval` is defined with a value greater than 0, it represents the interval
in minutes at which the yara connector will pause its work and execute an external
shell script.  A sample script, `vacuumscript.sh`  is provided within the `scripts` folder
of the current Yara connector installation. After execution, the Yara connector continues with
its work.

> _**NOTE:** As a safety for this feature, if an interval is defined but no script is defined, nothing is done.
> By default, no script is defined._

```ini
;
; The use of the utility script is an ADVANCED FEATURE and should be used with caution!
;
; If "utility_interval" is greater than 0 it represents the interval in minutes after which the yara connector will
; pause to execute a shell script for general maintenance. This can present risks. Be careful what you allow the
; script to do, and use this option at your own discretion.
;
utility_interval=-1
utility_script=./scripts/vacuumscript.sh
```

## Yara Agent Build Instructions 

The dockerfile in the top-level of the repo contains a centos7 environment for running, building, and testing 
the connector. 

The provided script `docker-build-rpm.sh` will use docker to build the project, and place the RPM(s) in $PWD/RPMS. 


##### Command-line Options
```text
usage: main.py [-h] --config-file CONFIG_FILE [--log-file LOG_FILE]
               [--output-file OUTPUT_FILE] [--validate-yara-rules] [--debug]

Yara Agent for Yara Connector

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        Location of the config file
  --log-file LOG_FILE   Log file output (defaults to `local` folder)
  --output-file OUTPUT_FILE
                        output feed file (defaults to `local` folder)
  --validate-yara-rules
                        ONLY validate yara rules in a specified directory
  --debug               Provide additional logging

```
###### --config-file
Provides the path of the configuration file to be used _**(REQUIRED)**_

###### --log-file
Provides the path of the yara log file.  If not supplied, defaults to `local/yara_agent.log`
within the current yara package.

###### --output-file
Provides the path containing the feed description file.  If not supplied, defaults to
`feed.json` in the same location as the configured `feed_database_dir` folder.

###### --validate-yara-rules
If supplied, yara rules will be validated and the script will exit.

#### Example Cron Entry
_[TBD]_

# Dev install 

Use git to retrieve the project, create a new virtual environment using python3.6+ and use pip to install the requirements:

```
git clone https://github.com/carbonblack/cb-yara-connector
pip3 install -r requirements.txt
```
