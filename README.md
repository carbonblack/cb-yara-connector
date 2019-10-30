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
> 1) The use of `{YARA}` is a placeholder representing the location of the yara package's `main.py` file,
> allowing for the use of relative paths to the package itself.
> 2) All paths can use `~` to access your home directory, so you can locate files there as well.

#### Running Yara Agent Manually

```shell script
./yara_agent --config-file=<config file location>
```

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
	yara_rules_dir={YARA}/local/yara_rules
	
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
