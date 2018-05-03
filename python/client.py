'''
Copyright IBM Corp. 2018

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import json
import logging
import os
import shutil
import signal
import subprocess as sp
import sys
import traceback

import argparse
import requests
import urllib

openssl_cli_cnf_template_ = '''
####################################################################
[ req ]
default_bits       = 2048
default_keyfile    = {cli_key}
distinguished_name = server_distinguished_name
req_extensions     = server_req_extensions
string_mask        = utf8only
# prompt             = no

####################################################################
[ server_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default = US

stateOrProvinceName         = State or Province Name (full name)
stateOrProvinceName_default = TX

localityName         = Locality Name (eg, city)
localityName_default = Dallas

organizationName            = Organization Name (eg, company)
organizationName_default    = IBM

commonName           = Common Name (e.g. server FQDN or YOUR name)
commonName_default   = Data Store for Memcache

emailAddress         = Email Address
emailAddress_default = {cli_email}

####################################################################
[ server_req_extensions ]

subjectKeyIdentifier = hash
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
subjectAltName       = @alternate_names
nsComment            = "OpenSSL Generated Certificate for Data Store for Memcache"

####################################################################
[ alternate_names ]

DNS.1  = {cli_dns}
'''

class SSLClientConf(object):
    def __init__(self, cli_email, cli_subject, cli_dns, **kwargs):
        ###
        self.cli_email = cli_email
        self.cli_subject = cli_subject
        self.cli_dns = cli_dns
        self.cli_dir = kwargs.get('cli_dir', '.stunnel')
        self.cli_req  = kwargs.get('cli_req', '/'.join((self.cli_dir, 'clientcert.csr')))
        self.cli_conf = kwargs.get('cli_conf', '/'.join((self.cli_dir, 'openssl-client.conf')))
        self.cli_key  = kwargs.get('cli_key', '/'.join((self.cli_dir, 'clientkey.pem')))
        self.cli_cert = kwargs.get('cli_cert', '/'.join((self.cli_dir, 'clientcert.pem')))

    # SSL configuration file
    def openssl_cli_conf(self):
        return openssl_cli_cnf_template_.format(
            cli_key = self.cli_key,
            cli_email = self.cli_email,
            cli_dns = self.cli_dns,
        )

    def write_openssl_cli_conf(self):
        with open(self.cli_conf, 'w') as f:
            f.write(self.openssl_cli_conf())

    def read_openssl_cli_req(self):
        cli_req = ''
        with open(self.cli_req, 'r') as f:
            cli_req = f.read()
        return cli_req


    # generate server keys
    def openssl_generate_cli_keys_cmd(self):
        return '''\
        openssl req\
         -config {cli_conf}\
         -subj {subject}\
         -newkey rsa:2048 -sha256 -nodes\
         -out {cli_req}\
         -outform PEM'''.format(
            cli_conf = self.cli_conf,
            cli_req = self.cli_req,
            subject = self.cli_subject,
        )

stunnel_cli_cnf_template_ = '''
pid = {pidfile}
socket = r:TCP_NODELAY=1
#debug = 7
foreground = {foreground}

[udepot-client]
client = yes
accept = 0.0.0.0:{local_port}
connect = {remote_host}:{remote_port}
cert = {cli_cert}
key = {cli_key}
CAfile = {ca_cert}
verify = 2
'''

class StunnelClient():
    def __init__(self, ssl_cl, **kwargs):
        self.ssl_cl = ssl_cl
        self.cli_dir = self.ssl_cl.cli_dir
        self.cli_key = self.ssl_cl.cli_key
        self.cli_cert = self.ssl_cl.cli_cert
        self.ca_cert = kwargs.get('ca_cert', '/'.join((self.cli_dir, 'cacert.pem')))
        self.cli_stunnel_pidfile = kwargs.get('cli_pidfile', '/'.join((self.cli_dir, 'stunnel-client.pid')))
        self.cli_stunnel_pidfile = os.path.realpath(self.cli_stunnel_pidfile)
        self.cli_stunnel_conf = kwargs.get('cli_stunnel_conf', '/'.join((self.cli_dir, 'stunnel-cli.conf')))
        self.cli_stunnel_fg = kwargs.get('cli_stunnel_fg', 'no')
        # accept
        self.local_port = kwargs.get('local_port', '11211')
        # connect
        self.remote_port = kwargs.get('remote_port', '11212')
        self.remote_host = kwargs.get('remote_host', '127.0.0.1')

    def stunnel_conf(self):
        return stunnel_cli_cnf_template_.format(
            pidfile = self.cli_stunnel_pidfile,
            remote_host = self.remote_host,
            remote_port = self.remote_port,
            local_port = self.local_port,
            cli_cert = self.cli_cert,
            cli_key = self.cli_key,
            ca_cert = self.ca_cert,
            foreground = self.cli_stunnel_fg,
        );

    def write_stunnel_cli_conf(self):
        with open(self.cli_stunnel_conf, 'w') as f:
            f.write(self.stunnel_conf())

def call(cmd):
    logging.debug('RUN:{}'.format(cmd))
    p = sp.Popen(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    (out, err) = p.communicate()
    logging.debug('rc={0} out={1} err={2}'.format(p.returncode, out, err))
    return (p.returncode == 0, out, err)

class DsfmClient():
    def __init__(self, apikey, instance_crn, stunnel_conf_path, dsfm_setup_url):
        self.apikey = apikey
        self.instance_crn = instance_crn
        self.user_agent = 'Data Store for Memcache client'
        #self.request_headers.add('User-Agent', self.user_agent)
        self.stunnel_path = stunnel_conf_path
        self.dsfm_setup_url = dsfm_setup_url
        self.access_token = ''
        self.logged_in = False

    def login(self):
        if sys.version_info >= (3, 0):
            data = urllib.parse.urlencode({'grant_type': 'urn:ibm:params:oauth:grant-type:apikey', 'apikey': self.apikey})
        else:
            data = urllib.urlencode({'grant_type': 'urn:ibm:params:oauth:grant-type:apikey', 'apikey': self.apikey})

        url = 'https://iam.stage1.bluemix.net/identity/token'
        headers = {
	    'Content-Type': 'application/x-www-form-urlencoded',
	    'Accept': 'application/json',
        }
        res = requests.post(url=url, headers=headers, data=data, verify=False)
        # logging.info(res.__dict__)
        if res.ok:
            json_response = res.json()
            self.access_token = json_response['access_token']
            self.logged_in = True
            logging.debug('Authentication successful\n received token:%s', self.access_token)

        else:
            logging.info('Authentication failed with http code {}'.format(res.status_code))


    def create_ssl_key(self, ssl_cnf):
        if not self.logged_in:
            logging.info('Not logged in.')
            return False
        # Client: generate keys
        ret = False
        try:
            ssl_cnf.write_openssl_cli_conf()
            ret,_,_ = call(ssl_cnf.openssl_generate_cli_keys_cmd())
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=2, file=sys.stdout)
            return False
        return ret

    def dsfm_authenticate_setup(self, ssl_cnf):
        if not self.logged_in:
            logging.info('Not logged in.')
            return False
        data = {
            'crn_instance_id' : self.instance_crn,
            'client_key_pem' : ssl_cnf.read_openssl_cli_req(),
            'iam_api_token' : self.access_token
        }
        url = self.dsfm_setup_url
        headers = {
	    'Content-Type': 'application/json',
	    'Accept': 'application/json',
        }
        logging.debug(data)
        res = requests.post(url=url, headers=headers, json=data, verify=False)
        logging.debug(res.__dict__)
        if res.ok:
            json_response = res.json()
            self.cli_cert_string = json_response['cli_cert']
            self.ca_cert_string = json_response['ca_cert']
            self.dsfm_endpoint = json_response['dsfm_endpoint']
            self.dsfm_port = json_response['dsfm_port']
            logging.debug('Service instance authotization and setup success')
        else:
            logging.info('Service authorization and setup failed with {}.'.format(res.status_code))
            return False

        return True

    def configure_stunnel(self, ssl_cnf):
        if not self.logged_in:
            logging.info('Not logged in.')
            return False
        try:
            # write signed cli pem
            with open(ssl_cnf.cli_cert, 'w') as f:
                f.write(self.cli_cert_string)
            cli = StunnelClient(ssl_cnf,
                                        remote_host = self.dsfm_endpoint,
                                        remote_port = self.dsfm_port,
                                        local_port = 11211,
                                        cli_stunnel_fg = 'no')
            # write ca cert
            with open(cli.ca_cert, 'w') as f:
                f.write(self.ca_cert_string)

            # Client: written stunel conf and start stunnel
            cli.write_stunnel_cli_conf()
            cli_stunnel = sp.Popen('stunnel {}'.format(cli.cli_stunnel_conf), shell=True)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback,
                                      limit=2, file=sys.stdout)
            return False
        return True

def main(args):
    outcome = {'result' : 'failure'}
    try:
        stunnel_exists = is_stunnel_installed()
        if not stunnel_exists:
            logging.warning('stunnel does not seem to exist. Did you install it?')
            logging.warning('Aborting.')
            return {'result': 'notexists'}
        stunnel_running = is_stunnel_running(args)
        if stunnel_running:
            logging.warning('stunnel seems to already be running.'\
                            'Please check and if this is expected (e.g., stunnel '\
                            'running for another application) '\
                            'please consider providing a different --stunnel_conf_path.')
            logging.warning('In case you want to delete the current client configuration'\
                            'and create a new one, please do a --cleanup first.')
            logging.warning('Aborting.')
            return {'result': 'running'}
        if not os.path.isdir(args.stunnel_conf_path):
            os.mkdir(args.stunnel_conf_path)
        # 1. create client
        cl = DsfmClient(args.apikey, args.instance_crn, args.stunnel_conf_path, args.dsfm_setup_url)

        # 2. try to login to bluemix and receive an iam token
        logging.info('Trying to retrieve a login token based on the provided apikey.')
        cl.login()
        if not cl.logged_in:
            return outcome

        # 3. create local ssl key
        ssl_cnf = SSLClientConf(args.email,
                                args.ssl_subject,
                                args.domain,
                                cli_dir=args.stunnel_conf_path)
        logging.info('Creating local ssl keys.')
        ret = cl.create_ssl_key(ssl_cnf)
        if not ret:
            logging.warning('Failed to create ssl keys.')
            return outcome

        logging.info('Asking for authentication and authorization against {}.'.format(cl.dsfm_setup_url))
        logging.info('This might take a while.')

        # 4. authenticate with service and get the key certified
        ret = cl.dsfm_authenticate_setup(ssl_cnf)
        if not ret:
            logging.warning('Failed to authenticate with dsfm service.')
            return outcome

        logging.info('Authorization success. '\
                     'Setting up end-to-end ssl encryption using stunnel.')

        # 5. setup and launch stunnel, verify that it works
        ret = cl.configure_stunnel(ssl_cnf)
        if not ret:
            logging.warning('Failed to configure stunnel.')
            return outcome

        # 6. test that connection works, do a simple memcache get stats
        logging.info('Setup complete, checking memcache protocol with a non-mutable stats command.')
        ret,out,err = call('echo stats | nc localhost 11211 -4')
        logging.debug('memcache server response stdout={0} stderr={1}'.format(out, err))
        if ret != 0:
            logging.warning('Failed to run memcache command.')
            return outcome
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback,
                                  limit=2, file=sys.stdout)
        return outcome

    return {'result': 'success', 'client-conf': cl.__dict__ }

def is_stunnel_installed():
    found=False
    for p in os.environ['PATH'].split(':'):
        abspath = os.path.join(p, 'stunnel')
        if os.path.exists(abspath):
            found=True
            break
    return found

def is_stunnel_running(args):
    ssl_cnf = SSLClientConf(args.email,
                            args.ssl_subject,
                            args.domain,
                            cli_dir=args.stunnel_conf_path)
    cli = StunnelClient(ssl_cnf)
    return os.path.isfile(cli.cli_stunnel_pidfile)

def cleanup(args):
    try:
        ssl_cnf = SSLClientConf(args.email,
                                args.ssl_subject,
                                args.domain,
                                cli_dir=args.stunnel_conf_path)
        cli = StunnelClient(ssl_cnf)
        if is_stunnel_running(args):
            with open(cli.cli_stunnel_pidfile) as f:
                cli_stunnel_pid = int(f.read())
                logging.info('Killing stunnel process w/ pid={}.'.format(cli_stunnel_pid))
                os.kill(cli_stunnel_pid, signal.SIGTERM)
        else:
            logging.info('stunnel does not seem to be running.')
        stunnel_dir_exists = os.path.isdir(cli.cli_dir)
        if stunnel_dir_exists:
            logging.info('About to remove folder {cli_dir} and all '
                         'its contents.'.format(cli_dir=cli.cli_dir))
            if sys.version_info >= (3, 0):
                user_arg = input('Proceed (y/n)?')
            else:
                user_arg = raw_input('Proceed (y/n)?')
            if user_arg == 'y':
                logging.info('Removing folder {cli_dir} and '\
                             'all its contents.'.format(cli_dir=cli.cli_dir))
                shutil.rmtree(cli.cli_dir)
        else:
            logging.info('stunnel dir {0} does not seem to exist. '\
                         'Did you already run cleanup or did you '\
                         'provide the wrong path?'.format(cli.cli_dir))
        logging.info('Cleanup complete.')
        return
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback,
                                  limit=2, file=sys.stdout)

    logging.info('Cleanup failed.')

if __name__ == '__main__' :
    parser = argparse.ArgumentParser(
        description='Data Store for Memcache client setup',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--apikey', help='Bluemix account api key', required=True)
    parser.add_argument('--instance_crn', help='Bluemix service instance crn',
                        default='crn%3Av1%3Astaging%3Apublic%3Adata-store-for-memcache%3Aus-south%3Aa%2Ftest-test-01')
    parser.add_argument('--dsfm_setup_url', default = 'https://dsfm.stage1.mybluemix.net/auth/instance', help='URL for service setup')
    parser.add_argument('--stunnel_conf_path', default = os.path.join(os.environ['HOME'], '.stunnel'), help='path for stunnel setup files')
    parser.add_argument('--email', default = 'client@client.com', help='client email')
    parser.add_argument('--ssl_subject', default = '/C=US/ST=TX/L=Dallas/O=Client/CN=client.com', help='client ssl info')
    parser.add_argument('--domain', default = 'client.com', help='client domain')
    parser.add_argument('--remote_host', default = 'client.com', help='client domain')
    parser.add_argument('--cleanup', dest='cleanup', action='store_true',
                        help='cleanup stunnel configuration')
    parser.add_argument('--debug', dest='debug', action='store_true', help='print debug iformation')
    args = parser.parse_args()
    log_level = logging.INFO
    if args.debug:
        log_level=logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', level=log_level,
                        datefmt='%Y-%m-%d %H:%M:%S')
    if args.cleanup:
        logging.info('User requested cleanup. Stunnel configuration will be purged,')
        logging.info('and stunnel daemon will be killed.\n'\
                     'This might interrupt your Data Store for Memcache client.')
        if sys.version_info >= (3, 0):
            user_arg = input('Proceed (y/n)?')
        else:
            user_arg = raw_input('Proceed (y/n)?')
        if user_arg == 'y':
            cleanup(args)
    else:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        ret = main(args)
        if ret['result'] == 'success':
            logging.info('Successfully setup Data Store for Memcache client.')
            logging.info('You can now use your memcache client on localhost:11211.')
        elif ret['result'] == 'running':
            logging.debug('Data Store for Memcache client instance seems to exist.')
        elif ret['result'] == 'notexists':
            logging.debug('Data Store for Memcache client requires stunnel to be installed.')
        else:
            logging.info('Failed to setup data store for memcache client.')
            logging.info('Please contact support at {}.'.format('https://ibm-cloudplatform.slack.com/messages/C8341DHT7'))
