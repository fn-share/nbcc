# nbc/wallet: NBC Wallet, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import time, traceback
from random import randint

from .. import util
from ..util.hash import hash160
from ..util.ecdsa import SECP256k1 as curve
from ..util.ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ..util.ecdsa.util import string_to_number, number_to_string, randrange, sigencode_der, sigdecode_der

import getpass
from binascii import hexlify, unhexlify
from ..util.pyaes.aes import AESModeOfOperationCBC as AES

if bytes == str:      # python 2
  def _bytes(t):
    return bytes(bytearray(t))
else: _bytes = bytes  # python 3

def _aesEncrypt(sText, passphrase):
  if not isinstance(passphrase,bytes):
    passphrase = passphrase.encode('utf-8')
  passphrase = passphrase[:16].ljust(16,b'\x00')
  aes = AES(passphrase)
  
  m,n = divmod(len(sText),16)
  if n:
    sText = sText + b'\x00' * (16 - n)  # align to 16 * N
    m += 1
  
  sEncoded = b''; iFrom = 0
  for i in range(m):
    sEncoded += aes.encrypt(sText[iFrom:iFrom+16])
    iFrom += 16
  return sEncoded

def _aesDecrypt(sText, passphrase=''):
  m,n = divmod(len(sText),16)
  if m == 0 or m >= 16 or n != 0:  # encrypted text should be 16 * N
    raise ValueError('invalid encrypted text')
  
  while not passphrase:
    passphrase = getpass.getpass('Passphrase:').strip()
  if not isinstance(passphrase,bytes):
    passphrase = passphrase.encode('utf-8')
  passphrase = passphrase[:16].ljust(16,b'\x00')
  aes = AES(passphrase)
  
  sDecoded = b''; iFrom = 0
  for i in range(m):
    sDecoded += aes.decrypt(sText[iFrom:iFrom+16])
    iFrom += 16
  return sDecoded

def _keyFromPoint(point, compressed):
  key = ( b'\x04' +
          number_to_string(point.x(),curve.order) +
          number_to_string(point.y(),curve.order) )
  if compressed:
    key = util.key.compress_public_key(key)
  return key

def _sigencode(r, s, order):
  return unhexlify(b'%064x' % r) + unhexlify(b'%064x' % s)  # fixed to 64 bytes

def _sigdecode(s, order):
  return (int(hexlify(s[:32]),16),int(hexlify(s[32:]),16))

# Class Address descript secp256k1 curve address, it is used for
# blockchain account.
#
# The account usually take a public key and a private key, however
# private key can be abscent, the account supports verify signature
# but no making signature if private key abscent, nevertheless,
# if private key is included, the public key can be calculated
# from private key, and the account both support making signature
# and verify signature.
# 
# Args:
#   pub_key (None or bytes): None means public key is abscent (it 
#     will depend to `priv_key`), pass 33-bytes means it is
#     compressed public key and its first byte should be b'\x02'
#     or b'\x03', pass 65-bytes means it is uncompressed public
#     key and its first byte should be b'\x04'
#   priv_key (None or bytes): None for private key abscent, 
#     otherwize it should be WIF format string, argument pub_key 
#     and priv_key can not both be None
#   ver (bytes): version of account, it usually take b'\x00' 
#     that means version 0
# 
# Examples:
#   >>> Address(public_key_33_bytes)
#   <nbcc.wallet.address.Address object at 0x105205940>
#   >>> from nbcc import util
#   >>> priv = util.key.privkey_to_wif(private_key_32_bytes)
#   >>> Address(priv_key=priv)
#   <nbcc.wallet.address.Address object at 0x10543da90>
class Address(object):
  def __init__(self, pub_key=None, priv_key=None, ver=b'\x00'):
    self._compressed = False
    self._priv_key = priv_key
    self._ver = ver  # in BTC, ver can be b'\x00'~b'\xff', b'\x6f' for testnet
    
    if priv_key:
      if pub_key is not None:
        raise ValueError('cannot specify public and private key both')
      assert isinstance(priv_key,bytes)
      
      # this is a compressed private key
      ch = ord(priv_key[:1])
      if ch == 76 or ch == 75:  # 76 is 'L', 75 is 'K'
        self._compressed = True
      elif ch != 53:            # 53 is '5'
        raise ValueError('unknown private key type: %r' % priv_key[0])
      
      secexp = string_to_number(util.key.privkey_from_wif(self._priv_key))
      self._point = point = curve.generator * secexp
      pub_key = _keyFromPoint(point,False)
    else:
      self._priv_key = None
      self._point = None
    
    self._comp_pubkey = None
    self._sign_key = None
    self._verify_key = None
    
    if pub_key:
      assert isinstance(pub_key,bytes)
      
      ch = ord(pub_key[:1])
      if ch == 4:  # prefix with 0x04 means decompressed
        if len(pub_key) != 65:
          raise ValueError('invalid uncomprssed public key')
      elif ch == 2 or ch == 3:
        self._compressed = True
        self._comp_pubkey = pub_key  # cache the value since it used very common
        pub_key = util.key.decompress_public_key(pub_key)
      else:
        raise ValueError('invalid public key')
      self._pub_key = pub_key
    else:
      raise ValueError('no address parameters')
    
    # public address, according to uncompressed
    self._address = util.key.publickey_to_address(self._pub_key,self._ver)
  
  # Get base58 encoded account address
  # Returns:
  #   human readable address string that encoded by base58
  def address(self):
    return self._address
  
  # Get public key hash by ripemd160(sha256d(public_key_33_bytes))
  # Returns:
  #   hash string in bytes
  def publicHash(self):
    return util.key.publickey_to_hash(self.publicKey())
  
  # Get compressed public key
  # Returns:
  #   public key in bytes
  def publicKey(self):
    if self._comp_pubkey is None:
      self._comp_pubkey = util.key.compress_public_key(self._pub_key)
    return self._comp_pubkey
  
  # Get private key
  # Returns:
  #   private key in bytes
  def _priv_key_(self):
    if self._priv_key is None:
      return None
    return util.key.privkey_from_wif(self._priv_key)  # the binary representation of private
  
  # Get fingerprint of public key
  # Returns:
  #   4 bytes fingerprint, by ripemd160(sha256(public_key33))[:4]
  def fingerprint(self):
    return hash160(self.publicKey())[:4]
  
  # Generate new random Address account
  # Args:
  #   ver (bytes): version of Address
  # Returns:
  #   4 bytes fingerprint, by ripemd160(sha256(public_key33))[:4]
  @staticmethod
  def generate(ver=b'\x00'):
    secexp = randrange(curve.order)             # return: 1 <= k < order
    key = number_to_string(secexp,curve.order)  # get 32 bytes number
    key += b'\x01'       # with compressed
    return Address(priv_key=util.key.privkey_to_wif(key),ver=ver)
  
  # Convert to public-key-uncompressed Address account
  # Returns:
  #   Address instance
  def decompress(self):
    if not self._compressed: return self
    
    if self._priv_key:
      return Address(priv_key=util.key.privkey_to_wif(self._priv_key_()),ver=self._ver)
    if self._pub_key:
      return Address(pub_key=util.key.decompress_public_key(self._pub_key),ver=self._ver)
    raise ValueError('address cannot be decompressed')
  
  # Convert to public-key-compressed Address account
  # Returns:
  #   Address instance
  def compress(self):
    if self._compressed: return self
    
    if self._priv_key:
      return Address(priv_key=util.key.privkey_to_wif(self._priv_key_()+b'\x01'),ver=self._ver)
    if self._pub_key:
      return Address(pub_key=self.publicKey(),ver=self._ver)
    raise ValueError('address cannot be compressed')
  
  # Get 32 bytes private key
  # Returns:
  #   private key in bytes
  def _get_priv(self):
    if self._priv_key is None: raise ValueError('invalid private key')
    return util.key.privkey_from_wif(self._priv_key)
  
  # Make signature
  # Args:
  #   data (bytes): the string to be sign
  #   single (bool): apply hash256() on `data` one time or twice
  #     True is one time, False is double time
  #   no_der (bool): the result signature in DER format or not,
  #     True for no DER format, False for DER format
  # Returns:
  #   signature in bytes
  def sign_ex(self, data, single=False, no_der=False):
    if self._sign_key is None:
      self._sign_key = SigningKey.from_string(self._get_priv(),curve)
    
    ha = util.sha256(data) if single else util.sha256d(data)
    sig_encode = _sigencode if no_der else sigencode_der
    return self._sign_key.sign_digest(ha,sigencode=sig_encode)
  
  # Verify signature
  # Args:
  #   data (bytes): the input string to be verified
  #   signature (bytes): the signature of `data`
  #   single (bool): apply hash256() on `data` one time or twice
  #     True is one time, False is double time
  #   no_der (bool): `signature` in DER format or not,
  #     True for no DER format, False for DER format
  # Returns:
  #   return bytes value, if return b'' means verify failed,
  #   otherwise return 32 bytes of hash string means verify OK
  def verify_ex(self, data, signature, single=False, no_der=False):
    if self._verify_key is None:
      if self._priv_key:
        secexp = string_to_number(util.key.privkey_from_wif(self._priv_key))
        point = curve.generator * secexp
        self._verify_key = VerifyingKey.from_public_point(point,curve)
      else:
        if self._pub_key is None: raise ValueError('invalid public key')
        self._verify_key = VerifyingKey.from_string(util.key.decompress_public_key(self._pub_key)[1:],curve)
    
    try:
      ha = util.sha256(data) if single else util.sha256d(data)
      sig_decode = _sigdecode if no_der else sigdecode_der
      if self._verify_key.verify_digest(signature,ha,sigdecode=sig_decode):
        return ha
    except BadSignatureError:
      pass
    except:
      traceback.print_exc()
    return b''
  
  # Make signature by doulbe hash256() on `data` and with DER format
  # Args:
  #   data (bytes): the string to be sign
  # Returns:
  #   signature in bytes
  def sign(self, data):
    return self.sign_ex(data)
  
  # Verify signature, the `signature` come from double hash256()
  #   on `data` and it is in DER format
  # Args:
  #   data (bytes): the input string to be verified
  #   signature (bytes): the signature of `data`
  # Returns:
  #   return bool value, True for verify passed, and False for 
  #   failed (not pass)
  def verify(self, data, signature):
    return self.verify_ex(data,signature) != b''
  
  # Make signature by doulbe hash256() on `data` and with no DER
  #   format
  # Args:
  #   data (bytes): the string to be sign
  # Returns:
  #   signature in bytes
  def sign_noder(self, data):
    return self.sign_ex(data,no_der=True)
  
  # Verify signature, the `signature` come from double hash256()
  #   on `data` and it is not in DER format
  # Args:
  #   data (bytes): the input string to be verified
  #   signature (bytes): the signature of `data`
  # Returns:
  #   return bytes value, if return b'' means verify failed,
  #   otherwise return 32 bytes of hash string means verify OK
  def verify_noder(self, data, signature):
    return self.verify_ex(data,signature,no_der=True)
  
  def __str__(self):
    privateKey = 'None'
    if self._priv_key: privateKey = '**redacted**'
    return '<Address address=%s private=%s>' % (self._address,privateKey)
  
  # Dump account to dict result
  # Args:
  #   passphrase (str or bytes): for encrypting private key
  #   cfg (None or dict): pass None for creating new dict to hold
  #     result, also can pass dict value to hold dumping result
  # Returns:
  #   dict type result that hold dumping result
  def dump_to_cfg(self, passphrase='', cfg=None):
    cfg = cfg or {}
    account = { 'time':int(time.time()), 'encrypted':False, 'type':'default',
      'ver': self._ver.hex(), 'prvkey': None, 'pubkey': self.publicKey().hex() }
    
    privKey = self._priv_key
    if privKey:
      assert(len(privKey) <= 255)
      privKey = (b'%02x' % len(privKey)) + privKey
      
      if passphrase:
        privKey = _aesEncrypt(privKey,passphrase)
        account['encrypted'] = True
      
      account['prvkey'] = privKey.hex()
    
    fp = self.fingerprint().hex()
    accounts = cfg.get('accounts',None)
    if accounts is None:  # no account yet
      cfg['accounts'] = accounts = {}
    accounts[fp] = account
    cfg['default'] = fp
    
    return cfg
  
  # Load account from properties that hold in dict
  # Args:
  #   account (dict): hold all properties for account
  #   passphrase (str or bytes): for decrypting private key
  # Returns:
  #   return Address instance when successful
  @staticmethod
  def load_from_cfg(account, passphrase=''):
    pubKey = account['pubkey']; prvKey = account['prvkey']
    if prvKey:
      prvKey = unhexlify(prvKey)
      if account.get('encrypted'):
        prvKey = _aesDecrypt(prvKey,passphrase)
      
      try:
        orgLen = int(prvKey[:2],16); nowLen = len(prvKey)
        if nowLen < 2 + orgLen or nowLen > orgLen + 17:   # 17 is 2 + padding(15)
          raise ValueError('out of range')
        prvKey = prvKey[2:2+orgLen]  # first 2 bytes is original length
      except:
        raise ValueError('invalid private key')
    elif pubKey:
      pubKey = unhexlify(pubKey)
    
    ver = unhexlify(account.get('ver','00'))
    return Address(pub_key=pubKey,priv_key=prvKey,ver=ver)
