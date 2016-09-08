# GSI Authenticator

Enables GSI Authentication for Jupyterhub. Acquires an X509 certificate from a myproxy service.

Use with [SSH Spawner](https://github.com/NERSC/SSHSpawner) to authenticate to remote host with GSISSH

## Installation

Requires Python 3

```
python setup.py install 
```

## Configuration

See [jupyterhub_config.py](jupyterhub_config.py) for a sample configuration
