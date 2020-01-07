# Installing Yara Agent (Centos/RHEL 7+)

The Yara agent has two parts - a master and a potentially remote worker. 

The task-master service must be installed on the same system as Cb Response.

You can download the latest RPM from the github releases page, here(https://github.com/carbonblack/cb-yara-connector/releases/download/untagged-0b4e650fa85727815eb2/python-cb-threatconnect-connector-2.1.0-1.x86_64.rpm).

`yum install python-cb-yara-connector-<Latest>.rpm` will install the connector from the downloaded RPM.

The connector uses a configured directory containing yara rules, to efficiently scan binaries as they
are seen by the CB Response Server, and uses the generated threat information to produce an
intelligence feed for consumption by the CbR server.

The yara connector uses celery-queues to distribute work to remote workers - you will need to install and 
configure a broker (probbably, redis - but any broker compatible with celery 4.x+ will do) that is accessible
to the master node and to any worker(s).

# Dev install #

`git clone https://github.com/carbonblack/cb-yara-connector`
create a virtual environment with python3.6+ and install the requirements from the requirements.txt file
`pip3 install -r requirements.txt`

There is a docker file provided that setups a basic dev/build envirionment for the connector.
	
## Create Yara Agent Config

The installation process will create a sample configuration file 
`/etc/cb/integrations/cb-yara-connector/yaraconnector.sample.conf`
use this and create the real configuration file:
`cp /etc/cb/integrations/cb-yara-connector/yaraconnector.sample.conf /etc/cb/integrations/cb-yara-connector/yaraconnector.conf`

You must configure the postgres connection information for your CBR server , and the rest API location and credentails as well. 

~~~
;
; Cb Response postgres Database settings
;
postgres_host=127.0.0.1
postgres_username=cb
postgres_password=<Password from /etc/cb/cb.conf goes here>
postgres_db=cb
postgres_port=5002
~~~

You can find your postgres credentails in `/etc/cb/cb.conf`, the port, host, db, user should be as above.

You can find your API credential information in UI settings pane of your Carbon Black Response server.

~~~
;
; ONLY for worker_type of local
; Cb Response Server settings for scanning locally.
; For remote scanning please set these parameters in the yara worker config file
; Default: https://127.0.0.1
;
cb_server_url=https://localhost
cb_server_token=<API TOKEN GOES HERE>
~~~

You must configure `broker=` which sets the broker and results_backend for celery. You will set this appropriately as per the celery documentation - here (https://docs.celeryproject.org/en/latest/getting-started/brokers/).


The yarar-connector RPM contains a service that can be run in a few distinct configurations:
1) A local task master and remote worker(s) (RECOMMENDED)

This is the prefered mode of operation, using a celery broker to distribute analysis-tasks to a remote worker from a local task-master that keeps track of binaries resident in the configured server.

Install the connector on the cbr server - as the task-master and specify that the worker will be remote:

Read through the configuration file, specify the mode of operation,  the `mode=master` and `worker_type=remote`. This represents the configuration for the task master, which will distribute work over the configured broker/backend to each configured worker.

On the worker(s), install the rpm again, and in the configuration file specify the same CBR server information, but 
configure `mode=slave` and `worker_type=local`. This configuration file doesn't need postgres credentials, but does require rest API access to the Carbon Black Response server in question.

2) A local task master and local celery worker (NOTRECOMMENDED)
Read through the configuration file, specify the mode of operation as `mode=master` and `worker_type=local`.
A single daemon will scan binaries, local to the cbr instance. This configuration requires both the postgres , and REST API credentials from Carbon Black Response, in order to function correctly.

## Input your yara rules

The yara connector monitors the directory `/etc/cb/integrations/cb-yara-connector/yara_rules` for files (`.yar`) each specifying one or more yara rule. Your rules need to have `metadata` section with a `score: [1-10]` tag to appropriately score matching binaries.  This directory is configurable in your configuration file.

The yara connector is boudn by libyara.so's limitations for matched strings, number of compiler rules, etc. 

#### Running Yara Agent 

`systemctl start cb-yara-connector` will up the service using systemD. 
`systemctl stop cb-yara-connector` will gracefully stop the yara-connector.
`systemctl status -l cb-yara-connector` will display logging information. 

These commands are identical for both the master and any remote workers.

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
`/local/yara_feed.json` within the current yara package.

###### --validate-yara-rules
If supplied, yara rules will be validated and the script will exit.

#### Example Cron Entry
_[TBD]_

# Remote Worker Installation (Centos/RHEL 7)

* Make sure openssl-devel is installed

    ```
    sudo yum install openssl-devel
    ```

* Install Git and GCC

	```
	sudo yum install git
	sudo yum install gcc
	```

* Install Python 3.6

	```
	sudo yum install epel-release
	sudo yum install python36
	sudo yum install python36-devel
	```
	
* Install Redis
	
	```
	sudo yum install redis
	sudo systemctl start redis
	sudo systemctl enable redis
	```
	
	
* Install Supervisord

	```
	sudo yum install supervisor
	```
	
* Install Yara Worker

	```
	git clone https://github.com/carbonblack/cb-yara-connector.git
	cd cb-yara-connector
	git checkout yara_version2
	python3.6 -m venv venv
	source ./venv/bin/activate
	pip install -r requirements.txt
	deactivate
	```
	
	
* Create Yara Worker Config File `yara_worker.conf`

#### Example Yara Connector Master configuration

```ini
[general]

;
; Python Celery Broker Url. Set this full url stringg
; Example: redis://<ip_address>
;
broker_url=redis://127.0.0.1

mode=master

worker_type=remote

;
; Cb Response Server Configuration
; Used for downloading binaries
;
cb_server_url=https://localhost
cb_server_token=aafdasfdsafdsafdsa

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
broker_url=redis://127.0.0.1

mode=slave

worker_type=local

;
; Cb Response Server Configuration
; Used for downloading binaries
;
cb_server_url=https://localhost
cb_server_token=aafdasfdsafdsafdsa

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
