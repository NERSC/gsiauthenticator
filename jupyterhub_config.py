# Sample Configuration
c.JupyterHub.authenticator_class = 'gsiauthenticator.auth.GSIAuthenticator'
c.GSIAuthenticator.server = 'nerscca2.nersc.gov'
c.JupyterHub.cookie_max_age_days = 0.5

# Port for MyProxy Server
# c.GSIAuthenticator.port = 7512

# Lifetime of Certificate in seconds. This should match the equivalent
# value in `c.JupyterHub.cookie_max_age_days` eg. 0.5 days => 43200 seconds
# c.GSIAuthenticator.proxy_lifetime = 43200

# Prefix for writing out cert files. FIle will be <cert_path_prefix><username>
# c.GSIAuthenticator.cert_path_prefix = '/tmp/x509_'