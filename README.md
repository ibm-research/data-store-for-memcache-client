# IBM Data Store for Memcache Client

## Description

[IBM Data Store for Memcache](https://console.bluemix.net/catalog/services/data-store-for-memcache) Service provides a managed memcache service in the IBM Cloud that provides Non-Volatile Memory-based object caching to accelerate cloud applications.
Cloud applications extensively use DRAM-based caching solutions, like [Memcached](http://memcached.org/), to accelerate their workloads (e.g., [drupal](https://www.drupal.org/project/memcache), [wikipedia](http://www.datacenterknowledge.com/archives/2008/06/24/a-look-inside-wikipedias-infrastructure), [reddit](https://redditblog.com/2017/01/17/caching-at-reddit/), etc., transparently use memcache).
Data Store for Memcache replaces DRAM with modern NVM storage for caching using the same memcache API, offering orders of magnitude higher capacity, at a lower cost, while maintaining performance.

## API

Data Store for Memcache implements the ascii [memcache protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt).

## Usage

### Install dependencies

#### On Ubuntu:
`sudo apt-get install python-pip stunnel4 -y`  
`pip install -r requirements.txt`

#### On Mac:
`brew install stunnel`  
`pip install -r requirements.txt`


### Run client setup script

You'll need an [IBM cloud api key](https://console.bluemix.net/docs/iam/apikeys.html#platform-api-keys) to use the setup script. The service instance crn should be provided at your Data Store for Memcache service instance's dashboard.

`python python/client.py --apikey <your-ibm-cloud-api-key> --instance_crn <your-service-instance-crn>`
