import os

from traitlets import Unicode, Integer
from tornado import gen

from jupyterhub.auth import Authenticator

from gsiauthenticator.myproxy_login import myproxy_logon_py


class GSIAuthenticator(Authenticator):
    """Authenticate local Linux/UNIX users with GSI"""
    encoding = Unicode('utf8',
                       help="""The encoding to use for GSI"""
                       ).tag(config=True)
    server = Unicode('localhost',
                     help="""The MyProxy server to use for authentication."""
                     ).tag(config=True)

    port = Integer(7512,
                   help="""The MyProxy port to use"""
                   ).tag(config=True)

    cert_path_prefix = Unicode('/tmp/x509_',
                               help="""The path prefix for the cert/key file"""
                               ).tag(config=True)

    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate with GSI, and return the proxy certificate
        if login is successful.

        Return None otherwise.
        """
        username = data['username']
        try:
            resp = myproxy_logon_py(self.server, username, data['password'], port=self.port)
            # print(resp)
            if 'key' in resp:
                file = '%s%s' % (self.cert_path_prefix, username)
                with open(file, 'bw') as f:
                    os.chmod(file, 0o600)
                    f.write(resp['key'])
                    f.write(resp['cert'])
        except:
            if handler is not None:
                self.log.warning("GSI Authentication failed (%s@%s):",
                                 username, handler.request.remote_ip)
            else:
                self.log.warning("GSI Authentication failed: ")
            return None
        else:
            return username
