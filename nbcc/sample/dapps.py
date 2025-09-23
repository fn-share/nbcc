# dapps.py

import sys, os
if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor < 9):
  raise Exception('only support python v3.9+')

#---- config logger

import logging

_log_fmt = '%(asctime)s [%(name)s %(levelname)s] %(message)s'
logging.basicConfig(level=logging.INFO,format=_log_fmt)

logger = logging.getLogger(__name__)

#---- dbg_loop

import re, traceback
from threading import Timer

re_newline_ = re.compile(r'\r\n|\n|\r')

def run_code(data): 
  isExec = False
  lines = re_newline_.split(data)
  if len(lines) > 1:
    isExec = True
    lines = '\n'.join(lines)
    print('debug> exec multiple lines')
  
  else:  # only one line, 'exec' or 'eval'
    if not lines[0]:
      print('')
      return
    
    lines = lines[0]
    if lines == 'exit()':
      print('disable run exit()')
      return
    
    print('debug>',lines)
    try:
      compile(lines,'stdin','eval')
    except SyntaxError:
      isExec = True
  
  ret = None
  if isExec:
    try:
      exec(lines,globals())
    except Exception as e:
      ret = str(e)
      traceback.print_exc()
  else:
    try:
      ret = str(eval(lines,globals()))
    except Exception as e:
      ret = str(e)
      traceback.print_exc()
  
  if type(ret) != str: ret = ''
  print(ret)

def dbg_loop():
  while True: 
    s = input('>')
    if s == 'break': break
    
    if s == '*':  # press ctrl+d after empty line to quit inputing
      s = ''.join([line for line in sys.stdin])  # change to multi-line
    
    run_code(s)

if sys.flags.debug:     # when start with: python3 -d dapps.py
  Timer(8,dbg_loop).start()


#---- prepare RELAY_SERVER, APP_NAME

_relay_server = os.environ.get('RELAY_SERVER','')
if _relay_server.split(':')[0] in ('0.0.0.0','localhost','127.0.0.1'):
  RELAY_SERVER  = ''     # get access token by file: red-brick/var/.nbc_login
else:
  RELAY_SERVER  = _relay_server   # query access token by HTTP

def _auto_locate_dapp():
  # first find from sys.argv
  b = sys.argv[1:]; i = len(b) - 1
  while i >= 0:
    item = b[i]
    if item[:1] != '-' and len(item.split()) == 1:
      return item
    i -= 1
  
  # then random choose one
  b = os.listdir('.')
  for item in b:
    if item[:1] == '.': continue
    if os.path.isfile(os.path.join(item,'dapp_http.py')):
      return item    # for every dapp, dapp_http.py must in using
  raise RuntimeError('can not locate dapp root directory')

APP_NAME = _auto_locate_dapp()  # maybe many dapp-dir exists, you need denote one  # python3 dapps.py <dapp_name>

#---- prepare _lcns_info

from nbcc.dapp_lib.formatter import *
from nbcc.dapp_lib.lcns_loader import *

@compose((
  ('create_time',NI), ))
class DappConnBody: pass
  
@compose((
  ('name',VarStr),
  ('conn_num',NI), ))
class DappConnAmount: pass
  
def _load_lcns_info():
  lcns_file = os.path.join(APP_NAME,'license.dat')
  if not os.path.isfile(lcns_file): return None
  
  with open(lcns_file,'rb') as f:
    info = load_end_lcns(f.read(),DappConnBody,DappConnAmount)
  
  assert info[3]._._name.decode('utf-8') == APP_NAME
  return info

_lcns_info = _load_lcns_info() if _relay_server else None  # when connect to tr-client, we try locate license.dat file

#---- load config file and create FLASK app

import time, json, importlib

from urllib.request import urlopen
from urllib import parse as urlparse
from nbcc.dapp_lib.dapp_cfg import DappConfig

app = None
runtime = {}

_ignore_login_tok = bool(os.environ.get('IGNORE_LOGIN_TOK'))

if RELAY_SERVER:
  _login_token_dict = {}   # set((expired_tm{token:expired_tm}
  _get_token_prefix = 'http://' + RELAY_SERVER.split(':')[0] + ':49001/check_token?tok='
else:
  _rb_var_file = os.path.join(os.path.expanduser('~'),'red-brick','var')
  os.makedirs(_rb_var_file,exist_ok=True)
  _rb_var_file = os.path.join(_rb_var_file,'.nbc_login')
  
  _login_tokens = []       # [ [time_str,token], ... ]
  _login_renew_tm = 0

def check_token_ok(request):
  if _ignore_login_tok: return 'IGNORED'
  
  ret = ''
  tee_tok = request.cookies.get('_tee_tok_','')
  if not tee_tok: return ret
  
  if RELAY_SERVER:  # according to nbc-monitor
    # step 1: first check existing
    tm = _login_token_dict.get(tee_tok,0)
    now = int(time.time())
    if tm:
      if tm < now:
        _login_token_dict.pop(tee_tok,None)  # remove expired item
        return ret
      else: return tee_tok
    
    # step 2: then query from nbc-monitor
    url = _get_token_prefix + urlparse.quote(tee_tok)
    s = ''
    try:
      s = urlopen(url,timeout=5).read().decode('utf-8')
    except:   # try again when meet error
      try:
        s = urlopen(url,timeout=5).read().decode('utf-8')
      except: pass
    
    if s:
      try:
        # step 3: if check OK, save _login_token_dict, and try remove expired items
        expire_tm = int(s)
        _login_token_dict[tee_tok] = expire_tm
        ret = tee_tok   # check token OK
        
        if len(_login_token_dict) > 16:
          rmv = [k for k,v in _login_token_dict.items() if v < now]
          for k in rmv: _login_token_dict.pop(k,None)
      except:
        logger.warning(traceback.format_exc())
  
  else:   # according to local tr-client
    for _,tok in _login_tokens:
      if tok == tee_tok:
        return tok
    
    global _login_renew_tm
    now_tm = time.time()
    if now_tm - _login_renew_tm < 5: return ret  # ignore when just now reloaded
    
    try:
      tmp = []
      if os.path.isfile(_rb_var_file):
        b = open(_rb_var_file,'rt').read().splitlines()
        for line in b:
          b2 = line.split(',')
          if len(b2) == 2:
            tmp.append(b2)
            if b2[1] == tee_tok:
              ret = tee_tok
      
      _login_tokens[:] = tmp[-16:]  # max hold 16 items
      _login_renew_tm = now_tm
    except:
      logger.warning(traceback.format_exc())
  
  return ret

#----

def localhost_main(tcp_port, config, dist_name, inDebug=False):
  global app
  
  dapp_http = importlib.import_module(dist_name + '.dapp_http')
  static_dir = os.path.abspath(dist_name + '/static')
  app = dapp_http.config_http(static_dir,static_url='/static')
  if inDebug: app.debug = True
  
  from twisted.internet import reactor
  from twisted.web.resource import Resource
  from twisted.web.server import Site
  
  os.environ['APP_NAME'] = ''
  
  # import relayed-flask basic framework
  logger.info('start import %s.dapp ...',dist_name)
  local_web = importlib.import_module(dist_name + '.local_web')  # already call dapp_http.config_http()
  dapp = importlib.import_module(dist_name + '.dapp')
  
  _localhost_res = Resource()
  _localhost_res.putChild(APP_NAME.encode('utf-8'),dapp_http._flask_site)
  
  print('\nstarting web server (http://localhost:%s/%s/) ...\n' % (tcp_port,dist_name))
  reactor.listenTCP(tcp_port,Site(_localhost_res))
  reactor.run()

#----

_route_prefix  = ''
_old_app_route = None

_vendor_root = os.path.join(os.path.expanduser('~'),'.red-brick')
os.makedirs(_vendor_root,exist_ok=True)

def _localaccess(dapp):
  if isinstance(dapp,bytes): dapp = dapp.decode('utf-8')
  
  loc_acc_file = os.path.join(_vendor_root,'.localaccess')
  if os.path.isfile(loc_acc_file):
    try:
      cfg = json.loads(open(loc_acc_file,'rt').read())
      return cfg.get(dapp,None)
    except: pass
  return None

def _app_route(*args, **kwarg):
  prefix = _route_prefix
  if prefix: prefix = '/' + prefix
  if args:
    args = (prefix+args[0],) + args[1:]
  else: kwarg['rule'] = prefix + kwarg['rule']
  return _old_app_route(*args,**kwarg)

def root_main(config, relay_serv, dist_name, inDebug=False):
  global app, _old_app_route, _lcns_info
  
  dapp_http = importlib.import_module(dist_name + '.dapp_http')
  static_dir = os.path.abspath(dist_name + '/static')
  app = dapp_http.config_http(static_dir,static_url='/'+dist_name+'/static')
  if inDebug: app.debug = True
  
  _old_app_route = app.route   # save bound method
  app.route = _app_route       # replace old one
  
  b = relay_serv.rsplit(':',maxsplit=1)
  if _lcns_info:
    dapp_http.start_web_service((b[0],int(b[1])),_lcns_info)
    _lcns_info = None
  else:   # try start in localaccess mode
    conn_num = _localaccess(dist_name) or 2   # default connection num is 2
    dapp_http.start_web_service((b[0],int(b[1])),None,conn_num,dist_name)
  
  logger.info('start import %s.dapp ...',dist_name)
  local_web = importlib.import_module(dist_name + '.local_web') # already call dapp_http.config_http()
  dapp = importlib.import_module(dist_name + '.dapp')
  
  print('\nconnect to tr-client (%s:%s)\n' % (b[0],b[1]))
  from twisted.internet import reactor
  reactor.run()     # holding here

if __name__ == '__main__':
  assert APP_NAME
  runtime = importlib.import_module(APP_NAME).runtime
  runtime['APP_NAME'] = APP_NAME
  runtime['check_token_ok'] = check_token_ok
  
  config = DappConfig.load(APP_NAME,False,os.path.join(APP_NAME,'config.json'))
  runtime['config'] = config
  inDebug = bool(sys.flags.debug and sys.flags.interactive)
  
  if _relay_server:     # with TCP connection
    _route_prefix = APP_NAME
    root_main(config,_relay_server,APP_NAME,inDebug)
  
  else:   # listen at local machine
    runtime['LISTEN_PORT'] = lsn_port = os.environ.get('LISTEN_PORT','8000')
    localhost_main(int(lsn_port),config,APP_NAME,inDebug)

# Usage:
#   python3 -i -d -u dapps.py sample
# Or, without debugging:
#   python3 -u dapps.py sample
# Environment:
#   LISTEN_PORT=8000             # start local http server when RELAY_SERVER is empty, default is 8000
#   RELAY_SERVER=localhost:8001  # relay by tr-client that suggest using 8001 port, default RELAY_SERVER is empty
#   IGNORE_LOGIN_TOK=1           # cookie-var '_tee_tok_' pseudo checking, for testing
