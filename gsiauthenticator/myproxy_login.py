# $Id: myproxy_logon.py 672 2011-02-03 00:05:03Z shreyas $
#
# myproxy client
#
# Tom Uram <turam@mcs.anl.gov>
# 2005/08/04
#

import logging as _logging
import os
import socket
import re
from OpenSSL import crypto, SSL

class GetException(Exception): pass
class RetrieveProxyException(Exception): pass

logger = _logging.getLogger(__name__)

gsi_keys=dict()

def debuglevel(level):
    return 0


def create_cert_req(keyType = crypto.TYPE_RSA,
                    bits = 1024,
                    messageDigest = "md5"):
    """
    Create certificate request.

    Returns: certificate request PEM text, private key PEM text
    """

    # Create certificate request
    req = crypto.X509Req()

    # Generate private key
    pkey = crypto.PKey()
    pkey.generate_key(keyType, bits)

    req.set_pubkey(pkey)
    req.sign(pkey, messageDigest)

    cert_req_pem = crypto.dump_certificate_request(crypto.FILETYPE_ASN1,req)
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM,pkey)

    # Nasty OpenSSL 1.0 Hack
    # OpenSSL 1.0 changes the headers from "RSA PRIVATE KEY" to "PRIVATE KEY"
    try:
        ssl_version = SSL.SSLeay_version(SSL.SSLEAY_VERSION)
        logger.debug('Using SSL: ' + ssl_version)
        if ssl_version.startswith("OpenSSL 1"):
            key_pem = re.sub(r'BEGIN PRIVATE KEY', r'BEGIN RSA PRIVATE KEY', key_pem)
            key_pem = re.sub(r'END PRIVATE KEY', r'END RSA PRIVATE KEY', key_pem)
    except:
        logger.warn('Using older version of openSSL without SSLeay_version')

    return (cert_req_pem, key_pem)

def deserialize_response(msg):
    """
    Deserialize a MyProxy server response

    Returns: integer response, errortext (if any)
    """

    lines = msg.decode("utf-8").split('\n')
    # get response value
    resp=dict()
    for line in lines:
        try:
          (k,v)=line.split('=')
          resp[k]=v
        except:
          pass
    #responselines = filter( lambda x: x.startswith('RESPONSE'), lines)
    #responseline = responselines[0]
    #response = int(responseline.split('=')[1])
    if resp['RESPONSE']=='0':
        response=0
    else:
        response=1
    #response=int(resp['RESPONSE'])

    # get error text
    errortext=""
    if 'ERROR' in resp:
      errortext = resp['ERROR']
    #errorlines = filter( lambda x: x.startswith('ERROR'), lines)
    #for e in errorlines:
    #    etext = e.split('=')[1]
    #    errortext += etext

    return response,errortext


def deserialize_certs(inp_dat):

    pem_certs = []

    dat = inp_dat
    import base64
    while dat:

        # find start of cert, get length
        ind = dat.find(b'\x30\x82')
        if ind < 0:
            break

        #len = 256*ord(dat[ind+2]) + ord(dat[ind+3])
        len = 256*dat[ind+2] + dat[ind+3]

        # extract der-format cert, and convert to pem
        c = dat[ind:ind+len+4]
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,c)
        pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM,x509)
        pem_certs.append(pem_cert)

        # trim cert from data
        dat = dat[ind + len + 4:]


    return pem_certs


CMD_GET="""VERSION=MYPROXYv2
COMMAND=0
USERNAME=%s
PASSPHRASE=%s
LIFETIME=%d\0"""

def myproxy_logon_py(hostname,username,passphrase,lifetime=43200,port=7512):
    """
    Function to retrieve a proxy credential from a MyProxy server

    Exceptions:  GetException, RetrieveProxyException
    """

    context = SSL.Context(SSL.SSLv3_METHOD)

    # disable for compatibility with myproxy server (er, globus)
    # globus doesn't handle this case, apparently, and instead
    # chokes in proxy delegation code
    context.set_options(0x00000800)

    # connect to myproxy server
    logger.debug("connect to myproxy server %s" %hostname)
    conn = SSL.Connection(context,socket.socket())
    conn.connect((hostname,port))

    # send globus compatibility stuff
    logger.debug("send globus compat byte")
    conn.write('0')

    # send get command
    logger.debug("send get command")
    cmd_get = CMD_GET % (username,passphrase,lifetime)
    conn.write(cmd_get)

    # process server response
    logger.debug("get server response")
    dat = conn.recv(8192)
    logger.debug("receive: %r" %dat)

    response,errortext = deserialize_response(dat)
    if response:
        logger.debug("error: " + errortext)
        raise GetException(errortext)
    else:
        logger.debug("server response ok")

    # generate and send certificate request
    # - The client will generate a public/private key pair and send a
    #   NULL-terminated PKCS#10 certificate request to the server.
    logger.debug("send cert request")
    certreq,privatekey = create_cert_req()
    conn.send(certreq)

    # process certificates
    # - 1 byte , number of certs
    dat = conn.recv(1)
    numcerts = dat[0]

    # - n certs
    logger.debug("receive certs")
    dat = conn.recv(8192)
    # if debuglevel(2):
    #     logger.debug('dumping cert data to "%s"' %settings.MYPROXY_DUMP_FILE)
    #     f = file(settings.MYPROXY_DUMP_FILE,'w')
    #     f.write(dat)
    #     f.close()

    # process server response
    logger.debug("get server response")
    resp = conn.recv(8192)
    response,errortext = deserialize_response(resp)
    if response:
        logger.debug("RetrieveProxyException " + errortext)
        raise RetrieveProxyException(errortext)
    else:
        logger.debug("server response ok")

    # deserialize certs from received cert data
    pem_certs = deserialize_certs(dat)
    if len(pem_certs) != numcerts:
        logger.debug("Warning: %d certs expected, %d received" % (numcerts,len(pem_certs)))

    # write certs and private key to file
    # - proxy cert
    # - private key
    # - rest of cert chain
    global gsi_keys
    gsi_keys[username]=privatekey

    return dict(cert=pem_certs[0], key=privatekey, calist=pem_certs[1:])



myproxy_logon = myproxy_logon_py


if __name__ == '__main__':
    import sys
    import optparse
    import getpass

    parser = optparse.OptionParser()
    parser.add_option("-s", "--pshost", dest="host",
                       help="The hostname of the MyProxy server to contact")
    parser.add_option("-p", "--psport", dest="port", default=7512,
                       help="The port of the MyProxy server to contact")
    parser.add_option("-l", "--username", dest="username",
                       help="The username with which the credential is stored on the MyProxy server")
    parser.add_option("-o", "--out", dest="outfile",
                       help="The username with which the credential is stored on the MyProxy server")
    parser.add_option("-t", "--proxy-lifetime", dest="lifetime", default=43200,
                       help="The username with which the credential is stored on the MyProxy server")
    parser.add_option("-d", "--debug", dest="debug", default=0,
                       help="Debug mode: 1=print debug info ; 2=print as in (1), and dump data to myproxy.dump")

    (options,args) = parser.parse_args()

    debug = options.debug

    # process options
    host = options.host
    if not host:
        print("Error: MyProxy host not specified")
        sys.exit(1)
    port = int(options.port)
    username = options.username
    if not username:
        if sys.platform == 'win32':
            username = os.environ["USERNAME"]
        else:
            import pwd
            username = pwd.getpwuid(os.geteuid())[0]
    lifetime = int(options.lifetime)

    outfile = options.outfile
    if not outfile:
        if sys.platform == 'win32':
            outfile = 'proxy'
        elif sys.platform in ['linux2','darwin']:
            outfile = '/tmp/x509up_u%s' % (os.getuid())

    # Get MyProxy password
    passphrase = getpass.getpass()

    # Retrieve proxy cert
    try:
        ret = myproxy_logon(host,username,passphrase,lifetime=lifetime,port=port)
        with open(outfile,'wb') as f:
            f.write(ret['key'])
        print("A proxy has been received for user %s in %s." % (username,outfile))
    except Exception as e:
        if debuglevel(1):
            import traceback
            traceback.print_exc()
        else:
            print("authentication failed")
            print (type(e))
