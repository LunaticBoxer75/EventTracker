# **EventTracker**: Event Driven Evidence Collection for Digital Forensics

## Installation
### Client-Side

**(You need to perform all the following steps being the root user.)**

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
Start with the [server setup](#server-side) now. After setting up the server, replace the elasticsearch `hosts` key in all the files in [conf files](./client/logstash/conf.d/) to the hostname/ip address and port of elasticsearch running on the server. If you want to skip the server setup, do not start the `logstash` service in the coming steps until the server setup is done.

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

### Server-Side

Install elasticsearch using the instructions given [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/install-elasticsearch.html) and kibana using the instructions given [here](https://www.elastic.co/guide/en/kibana/current/install.html). Make necessary changes to their configuration and make sure the elasticsearch address and port is accessible from the client(s).

After setting up elasticsearch and kibana, start them and do the initial kibana setup. Once that is done, look for **Kibana/Saved Objects** in kibana search bar and navigate to the link. Use the import button on the page opened to import the kibana dashboard from the file [export.ndjson](./server/export.ndjson).

Once import is done, navigate to **Dev Tools/Console** from the kibana search bar and execute the following two requests.
``` 
PUT login_activity
```
```
PUT login_activity/_mapping/
{
  "properties": {
    "geoip.geo.location": {
      "type": "geo_point"
    }
  }
}
```
The server setup is complete. Move to the next steps in the client setup now.