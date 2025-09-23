# dapp.py

from .local_web import app
assert app is not None, 'please call dapp_http.config_http() first'

import logging
logger = logging.getLogger(__name__)

from . import runtime
_config = runtime['config']
_check_token_ok = runtime['check_token_ok']

#----

import json, traceback

from flask import request
from urllib.request import urlopen
from urllib.error import HTTPError

CURR_DAPP_NAME  = 'sample'
CURR_DAPP_VER   = '0.1.0'
CURR_DAPP_LANG  = ''  # '' 'zh' 'en'
DAPP_STORE_SITE = 'https://nas.nb-chain.cn/www/dapps'

@app.route('/version')
def get_dapps_ver():
  try:
    newest = int(request.args.get('newest',0))
    if newest:
      try:
        events_folder = 'events' + ('_'+CURR_DAPP_LANG if CURR_DAPP_LANG else '')
        url = '%s/%s/last_%s.json' % (DAPP_STORE_SITE,events_folder,CURR_DAPP_NAME)
        res = urlopen(url,timeout=20).read()
      except HTTPError as e:
        if e.code == 400 and e.fp:
          return {'result':'failed','message':e.fp.read().decode('utf-8')}
        else: return {'result':'failed','message':'HTTPError'}
      except:
        logger.warning(traceback.format_exc())
        return {'result':'failed','message':'NETWORK_ERROR'}
      else:
        # must be {id,last_ver,favicon,name,package,parameter,desc}
        res = json.loads(res.decode('utf-8'))
        if 'package' in res:
          res['url'] = DAPP_STORE_SITE + '/' + res['package']
        res['result'] = 'success'
    else:
      res = {'result':'success'}
    
    res['version'] = CURR_DAPP_VER
    return res
  
  except: logger.warning(traceback.format_exc())
  return ('FORMAT_ERROR',400)
