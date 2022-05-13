# **EventTracker**: Event Driven Evidence Collection for Digital Forensics

## Installation
### 1. Client-Side
Install the following packages (Installation instructions for `ubuntu` distro are provided for reference)
  - Linux Audit Framework (`apt install auditd`)
  - MongoDB ([Refer here](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/))
  - Python 3 (`apt install python3-dev`)
  - Python 2 (`apt install python2`)
  - Logstash ([Refer here](https://www.elastic.co/guide/en/logstash/current/installing-logstash.html))
  - logstash-mongodb-input ([Refer here](https://github.com/phutchins/logstash-input-mongodb))
  - Volatility Framework ([Refer here](https://github.com/volatilityfoundation/volatility/wiki/Installation)) (Use the command `python setup.py install` to install the framework)
  - LiMe ([Refer here](https://github.com/504ensicsLabs/LiME))

After installing the above packages, clone the repository using the command:
```
git clone https://github.com/jains8844/EventTracker
```
Install the python requirements (prefer working in a virtual environment) using the following commands for the requirement files present in the cloned directory:
```
pip3 install -r ./client/requirements3.txt
pip2 install -r ./client/requirements2.txt
```
Create volatility profile using the instructions [here](https://opensource.com/article/21/4/linux-memory-forensics) and copy the profile to the directory (replace the respective versions in the directory path)
```
/usr/local/lib/python2-<version>/dist-packages/volatility-<version>.egg/volatility/plu‌​gins/overlays/linux
```
Copy the configuration files from [here](./client/logstash/conf.d) to `/etc/logstash/conf.d/` directory and [pipelines.yml](./client/logstash/pipelines.yml) to `/etc/logstash/`.

Start the `mongod`, `auditd` and `logstash` services using the command:
```
systemctl start <servicename>
```
Make necessary changes to the file [config.py](./client/config.py) and add the files/directories to be monitored to [files.txt](./client/files.txt).

After performing all the above steps, start the client by executing [fileMonitor.py](./client/fileMonitor.py) using the following command :
```
python3 fileMonitor.py
```