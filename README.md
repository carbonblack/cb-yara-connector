# Installing Yara Agent (Centos/RHEL 6)

The Yara agent must be installed on the same system as Cb Response.
	
* Download Yara Agent

	```
	wget -O /usr/share/cb/integrations/yara/yara_agent https://github.com/carbonblack/cb-yara-connector/releases/download/2.0.1/yara_agent
	```
	
* Download Yara Logo

	```
	wget -O /usr/share/cb/integrations/yara/yara-logo.png https://github.com/carbonblack/cb-yara-connector/releases/download/2.0.1/yara-logo.png
	```
	
## Create Yara Agent Config
Copy and modify either `sample_local.conf` or `sample_remote.conf` from the `samples` folder
to your desired location.


> NOTES:
> 1) All paths can use `~/` to allow the use of the user's home directory.

#### Running Yara Agent Manually

```shell script
./yara_agent --config-file=<config file location>
```

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

#### Example Yara Worker Config File

	[general]

	;
	; Python Celery Broker Url. Set this full url string for Redis
	; Example: redis://<ip_address>
	;
	broker_url=redis://127.0.0.1
	
	;
	; Cb Response Server Configuration
	; Used for downloading binaries
	;
	cb_server_url=
	cb_server_token=
	
	;
	; Directory for temporary yara rules storage
	; WARNING: Put your yara rules with the yara agent.  This is just temporary storage.
	;
	yara_rules_dir=./yara_rules
	
* Copy, modify and save to `yara_worker.conf`
	
#### Run Yara Worker Manually

	celery -A tasks worker --config-file=yara_worker.conf --concurrency=10 --loglevel=info
	
#### Example Supervisor Config

	[program:yara_workers]
	stdout_logfile=/var/log/yara_worker.log
	stderr_logfile=/var/log/yara_worker.log
	user=<username>
	directory=/home/<username>/cb-yara-connector
	command=/home/<username>/cb-yara-connector/venv/bin/celery -A tasks worker --config-file=yara_worker.conf --concurrency=10 --loglevel=info
	autostart=true
	autorestart=true
	
* Copy the above, modify and add to `/etc/supervisord.conf`

* Enabled Supervisor

	```
	systemctl enable supervisord
	```
	
* Restart Supervisor

	```
	systemctl restart supervisord
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

## Yara Agent Build Instructions (Centos 6)

### Install Dependencies

* zlib-devel
* openssl-devel
* sqlite-devel

### Install Python 3.6

	
	./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
	make
	make altinstall


### Create VirtualEnv


	python3.6 -m venv venv-build
	source ./venv-build/bin/activate
	pip install -r requirements.txt


### Create Executable


	pyinstaller main.spec
