# dapp.py

# import app, APP_NAME, get_url_root
from .local_web import *
assert app is not None, 'please call dapp_http.config_http() first'

import logging
logger = logging.getLogger(__name__)

#----

@app.route('/test')
def do_test():
  return 'test OK'
