# nbcc.wallet.Address 接口使用指南

## 1. 概述

`nbcc.wallet.Address` 类是基于 secp256k1 椭圆曲线的区块链账户地址实现，支持公钥/私钥管理、签名与验签等功能。该类适用于比特币及兼容链的账户体系。

### 主要特性

- 支持压缩公钥（33字节）和非压缩公钥（65字节）
- 支持 WIF 格式私钥导入
- 支持 DER 格式和非 DER 格式签名
- 支持单次和双次 hash 签名
- 支持账户配置的导入导出

## 2. 构造函数

```python
Address(pub_key=None, priv_key=None, ver=b'\x00')
```

### 参数说明

| 参数 | 类型 | 说明 |
|------|------|------|
| `pub_key` | None 或 bytes | 公钥。`None` 表示从私钥派生；33 字节为压缩公钥（首字节 `0x02` 或 `0x03`）；65 字节为非压缩公钥（首字节 `0x04`） |
| `priv_key` | None 或 bytes | 私钥，WIF 格式字符串。`pub_key` 和 `priv_key` 不能同时为 `None` |
| `ver` | bytes | 地址版本号，默认 `b'\x00'`（比特币主网） |

### 示例

```python
from nbcc.wallet import Address

# 方式 1：使用公钥创建账户（仅验签）
acc = Address(pub_key=public_key_bytes)

# 方式 2：使用私钥创建账户（可签名和验签）
acc = Address(priv_key=wif_private_key)

# 方式 3：指定版本号
acc = Address(priv_key=wif_private_key, ver=b'\x00')
```

## 3. 静态方法

### 3.1 generate() - 生成随机账户

生成一个新的随机账户。

```python
@staticmethod
def generate(ver=b'\x00')
```

**参数：**
- `ver` (bytes): 地址版本号，默认 `b'\x00'`

**返回：**
- `Address` 实例

**示例：**

```python
from nbcc.wallet import Address

# 生成随机账户
acc = Address.generate()

# 打印公钥信息
print("公钥 (hex):", acc.publicKey().hex())
print("公钥长度:", len(acc.publicKey()), "bytes")

# 打印私钥信息
print("私钥 WIF:", acc._priv_key.decode())
print("私钥 (hex):", acc._priv_key_().hex())
```

**输出示例：**
```
公钥 (hex): 0280e90912090b50db6e9f442f7499e17245916ef725c043ac1721128dd3f2d98f
公钥长度: 33 bytes
私钥 WIF: L3mC4iErKYVtvdodvBxDRSDeGdMj6EWgsRpgCendNJvYythhDmn1
私钥 (hex): c3382028249399d79fa19a8aecbc160740b496b523b1679463a7f3dd6726b97e
私钥长度: 32 bytes
```

### 3.2 load_from_cfg() - 从配置加载账户

从字典配置中加载账户。

```python
@staticmethod
def load_from_cfg(account, passphrase='')
```

**参数：**
- `account` (dict): 包含账户属性的字典
- `passphrase` (str 或 bytes): 解密私钥的密码

**返回：**
- `Address` 实例

## 4. 实例方法

### 4.1 公钥相关方法

#### publicKey() - 获取压缩公钥

```python
def publicKey(self)
```

**返回：**
- 33 字节压缩公钥（bytes）

#### publicHash() - 获取公钥哈希

计算公钥的哈希值：`ripemd160(sha256d(public_key))`

```python
def publicHash(self)
```

**返回：**
- 公钥哈希（bytes）

#### fingerprint() - 获取公钥指纹

计算公钥的 4 字节指纹：`ripemd160(sha256(public_key))[:4]`

```python
def fingerprint(self)
```

**返回：**
- 4 字节指纹（bytes）

### 4.2 地址相关方法

#### address() - 获取 Base58 编码地址

```python
def address(self)
```

**返回：**
- Base58 编码的地址字符串

#### compress() / decompress() - 公钥格式转换

```python
def compress(self)    # 转换为压缩公钥格式
def decompress(self)  # 转换为非压缩公钥格式
```

**返回：**
- 新的 `Address` 实例

### 4.3 签名方法

#### sign() - 标准签名（双次 hash + DER 格式）

对数据进行双次 hash256 后签名，结果为 DER 格式。

```python
def sign(self, data)
```

**参数：**
- `data` (bytes): 待签名数据

**返回：**
- DER 格式签名（bytes）

**示例：**

```python
from nbcc.wallet import Address

# 生成随机账号
acc = Address.generate()

# 使用私钥创建签名账户
acc2 = Address(priv_key=acc._priv_key)

# 使用公钥创建验签账户
acc3 = Address(pub_key=acc.publicKey())

# 签名
data = b'example'
signature = acc2.sign(data)
print("签名 (hex):", signature.hex())

# 验签
result = acc3.verify(data, signature)
print("验证结果:", "通过" if result else "失败")
```

#### sign_noder() - 非 DER 格式签名（双次 hash）

```python
def sign_noder(self, data)
```

**参数：**
- `data` (bytes): 待签名数据

**返回：**
- 非 DER 格式签名（64 字节，bytes）

#### sign_ex() - 扩展签名方法

支持自定义 hash 次数和签名格式。

```python
def sign_ex(self, data, single=False, no_der=False)
```

**参数：**
- `data` (bytes): 待签名数据
- `single` (bool): `True` 单次 hash，`False` 双次 hash（默认）
- `no_der` (bool): `True` 非 DER 格式，`False` DER 格式（默认）

**返回：**
- 签名（bytes）

**签名参数组合：**

| single | no_der | 说明 |
|--------|--------|------|
| False | False | 双次 hash + DER 格式（默认） |
| False | True | 双次 hash + 非 DER 格式 |
| True | False | 单次 hash + DER 格式 |
| True | True | 单次 hash + 非 DER 格式 |

**示例：**

```python
from nbcc.wallet import Address

acc = Address.generate()
acc2 = Address(priv_key=acc._priv_key)
acc3 = Address(pub_key=acc.publicKey())

data = b'example'

# 测试 1: 双次 hash + DER 签名
sig1 = acc2.sign_ex(data, single=False, no_der=False)
result1 = acc3.verify_ex(data, sig1, single=False, no_der=False)
print("双次 hash + DER:", "通过" if result1 != b'' else "失败")

# 测试 2: 双次 hash + 非 DER 签名
sig2 = acc2.sign_ex(data, single=False, no_der=True)
result2 = acc3.verify_ex(data, sig2, single=False, no_der=True)
print("双次 hash + 非DER:", "通过" if result2 != b'' else "失败")

# 测试 3: 单次 hash + DER 签名
sig3 = acc2.sign_ex(data, single=True, no_der=False)
result3 = acc3.verify_ex(data, sig3, single=True, no_der=False)
print("单次 hash + DER:", "通过" if result3 != b'' else "失败")

# 测试 4: 单次 hash + 非 DER 签名
sig4 = acc2.sign_ex(data, single=True, no_der=True)
result4 = acc3.verify_ex(data, sig4, single=True, no_der=True)
print("单次 hash + 非DER:", "通过" if result4 != b'' else "失败")
```

### 4.4 验签方法

#### verify() - 标准验签（双次 hash + DER 格式）

```python
def verify(self, data, signature)
```

**参数：**
- `data` (bytes): 原始数据
- `signature` (bytes): DER 格式签名

**返回：**
- `bool`: `True` 验证通过，`False` 验证失败

#### verify_noder() - 非 DER 格式验签（双次 hash）

```python
def verify_noder(self, data, signature)
```

**参数：**
- `data` (bytes): 原始数据
- `signature` (bytes): 非 DER 格式签名

**返回：**
- `bytes`: 空字节表示失败，非空（32 字节 hash）表示成功

#### verify_ex() - 扩展验签方法

```python
def verify_ex(self, data, signature, single=False, no_der=False)
```

**参数：**
- `data` (bytes): 原始数据
- `signature` (bytes): 签名
- `single` (bool): 与签名时的 `single` 参数一致
- `no_der` (bool): 与签名时的 `no_der` 参数一致

**返回：**
- `bytes`: 空字节表示失败，32 字节 hash 表示成功

### 4.5 配置导出方法

#### dump_to_cfg() - 导出账户配置

将账户信息导出为字典格式。

```python
def dump_to_cfg(self, passphrase='', cfg=None)
```

**参数：**
- `passphrase` (str 或 bytes): 加密私钥的密码
- `cfg` (None 或 dict): 用于存储结果的字典，`None` 则创建新字典

**返回：**
- `dict`: 包含账户配置的字典

## 5. 完整示例

### 5.1 创建账户与签名验签

```python
#!/usr/bin/env python3
"""完整示例：账户创建、签名与验签"""

from nbcc.wallet import Address

# ===== 步骤 1: 生成随机账户 =====
print("=== 生成随机账户 ===")
acc = Address.generate()
print("地址:", acc.address())
print("公钥:", acc.publicKey().hex())
print("私钥 WIF:", acc._priv_key.decode())

# ===== 步骤 2: 从私钥恢复账户 =====
print("\n=== 从私钥恢复账户 ===")
acc_from_priv = Address(priv_key=acc._priv_key)
print("地址一致:", acc_from_priv.address() == acc.address())

# ===== 步骤 3: 从公钥创建验签账户 =====
print("\n=== 从公钥创建账户 ===")
acc_from_pub = Address(pub_key=acc.publicKey())
print("公钥账户地址:", acc_from_pub.address())

# ===== 步骤 4: 签名与验签 =====
print("\n=== 签名与验签 ===")
data = b'Hello, Blockchain!'

# 使用私钥账户签名
signature = acc_from_priv.sign(data)
print("签名:", signature.hex())

# 使用公钥账户验签
verified = acc_from_pub.verify(data, signature)
print("验签结果:", "通过" if verified else "失败")
```

### 5.2 签名格式对比

```python
#!/usr/bin/env python3
"""签名格式对比示例"""

from nbcc.wallet import Address

acc = Address.generate()
data = b'test data'

print("=== 签名格式对比 ===")

# DER 格式签名
sig_der = acc.sign(data)
print(f"DER 签名长度: {len(sig_der)} 字节")
print(f"DER 签名开头: 0x{sig_der[0]:02x} (应为 0x30)")

# 非 DER 格式签名
sig_noder = acc.sign_noder(data)
print(f"非 DER 签名长度: {len(sig_noder)} 字节")

# 验证两种签名
print(f"DER 签名验证: {acc.verify(data, sig_der)}")
print(f"非 DER 签名验证: {acc.verify_noder(data, sig_noder) != b''}")
```

## 6. 注意事项

1. **私钥安全**：私钥应妥善保管，避免泄露。WIF 格式私钥以 `L` 或 `K` 开头表示压缩格式，以 `5` 开头表示非压缩格式。

2. **签名参数一致性**：使用 `sign_ex()` 和 `verify_ex()` 时，`single` 和 `no_der` 参数必须保持一致，否则验签会失败。

3. **公钥长度**：压缩公钥为 33 字节，非压缩公钥为 65 字节。地址计算基于公钥，相同私钥的压缩/非压缩公钥会产生不同的地址。

4. **验签返回值**：`verify()` 返回布尔值，而 `verify_ex()` 和 `verify_noder()` 返回字节串（空为失败，非空为成功）。

## 7. 测试脚本清单

| 文件名 | 说明 |
|--------|------|
| `test_create_account.py` | 生成随机账户并打印公钥私钥 |
| `test_sign_verify.py` | 标准签名与验签测试 |
| `test_single_hash.py` | 单次 hash 签名与验签测试 |
| `test_der_nonder.py` | DER 与非 DER 格式签名组合测试 |
