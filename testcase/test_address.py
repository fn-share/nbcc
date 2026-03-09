#!/usr/bin/env python3
"""nbcc.wallet.Address 接口测试用例"""

import unittest
from nbcc.wallet import Address


class TestAddressCreation(unittest.TestCase):
    """测试账户创建"""

    def test_generate_random_account(self):
        """测试生成随机账户"""
        acc = Address.generate()

        # 验证公钥
        pub_key = acc.publicKey()
        self.assertIsInstance(pub_key, bytes)
        self.assertEqual(len(pub_key), 33)  # 压缩公钥 33 字节
        self.assertIn(pub_key[0], (0x02, 0x03))  # 首字节应为 0x02 或 0x03

    def test_generate_with_version(self):
        """测试指定版本号生成账户"""
        acc = Address.generate(ver=b'\x00')
        self.assertIsNotNone(acc.address())

    def test_create_from_private_key(self):
        """测试从私钥创建账户"""
        acc1 = Address.generate()
        acc2 = Address(priv_key=acc1._priv_key)

        # 验证两个账户的公钥相同
        self.assertEqual(acc1.publicKey(), acc2.publicKey())

    def test_create_from_public_key(self):
        """测试从公钥创建账户"""
        acc1 = Address.generate()
        acc2 = Address(pub_key=acc1.publicKey())

        # 验证两个账户的公钥相同
        self.assertEqual(acc1.publicKey(), acc2.publicKey())

    def test_private_key_properties(self):
        """测试私钥属性"""
        acc = Address.generate()

        # 验证私钥 WIF 格式
        priv_wif = acc._priv_key
        self.assertIsInstance(priv_wif, bytes)
        self.assertIn(priv_wif[0], [ord('L'), ord('K'), ord('5')])  # WIF 格式开头

        # 验证原始私钥
        priv_raw = acc._priv_key_()
        self.assertIsInstance(priv_raw, bytes)
        self.assertEqual(len(priv_raw), 32)  # 原始私钥 32 字节


class TestAddressMethods(unittest.TestCase):
    """测试账户方法"""

    def setUp(self):
        """测试前准备"""
        self.acc = Address.generate()

    def test_address(self):
        """测试获取地址"""
        addr = self.acc.address()
        self.assertIsInstance(addr, str)
        self.assertGreater(len(addr), 0)

    def test_public_hash(self):
        """测试获取公钥哈希"""
        pub_hash = self.acc.publicHash()
        self.assertIsInstance(pub_hash, bytes)
        self.assertEqual(len(pub_hash), 20)  # ripemd160 输出 20 字节

    def test_fingerprint(self):
        """测试获取公钥指纹"""
        fp = self.acc.fingerprint()
        self.assertIsInstance(fp, bytes)
        self.assertEqual(len(fp), 4)  # 指纹 4 字节

    def test_compress_decompress(self):
        """测试公钥压缩与解压缩"""
        # 解压缩
        acc_uncompressed = self.acc.decompress()
        self.assertIsInstance(acc_uncompressed, Address)

        # 再压缩
        acc_compressed = acc_uncompressed.compress()
        self.assertIsInstance(acc_compressed, Address)

        # 验证压缩后公钥一致
        self.assertEqual(self.acc.publicKey(), acc_compressed.publicKey())


class TestSignVerify(unittest.TestCase):
    """测试签名与验签"""

    def setUp(self):
        """测试前准备"""
        self.acc = Address.generate()
        self.acc_priv = Address(priv_key=self.acc._priv_key)
        self.acc_pub = Address(pub_key=self.acc.publicKey())
        self.data = b'example'

    def test_sign_verify_standard(self):
        """测试标准签名验签（双次 hash + DER）"""
        signature = self.acc_priv.sign(self.data)
        result = self.acc_pub.verify(self.data, signature)
        self.assertTrue(result)

    def test_sign_verify_noder(self):
        """测试非 DER 格式签名验签（双次 hash）"""
        signature = self.acc_priv.sign_noder(self.data)
        result = self.acc_pub.verify_noder(self.data, signature)
        self.assertNotEqual(result, b'')  # 非空表示成功

    def test_sign_verify_single_hash_der(self):
        """测试单次 hash + DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=True, no_der=False)
        result = self.acc_pub.verify_ex(self.data, signature, single=True, no_der=False)
        self.assertNotEqual(result, b'')

    def test_sign_verify_single_hash_noder(self):
        """测试单次 hash + 非 DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=True, no_der=True)
        result = self.acc_pub.verify_ex(self.data, signature, single=True, no_der=True)
        self.assertNotEqual(result, b'')


class TestSignVerifyCombinations(unittest.TestCase):
    """测试签名验签参数组合"""

    def setUp(self):
        """测试前准备"""
        self.acc = Address.generate()
        self.acc_priv = Address(priv_key=self.acc._priv_key)
        self.acc_pub = Address(pub_key=self.acc.publicKey())
        self.data = b'example'

    def test_double_hash_der(self):
        """测试双次 hash + DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=False, no_der=False)
        result = self.acc_pub.verify_ex(self.data, signature, single=False, no_der=False)
        self.assertNotEqual(result, b'')

        # 验证 DER 格式签名以 0x30 开头
        self.assertEqual(signature[0], 0x30)

    def test_double_hash_noder(self):
        """测试双次 hash + 非 DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=False, no_der=True)
        result = self.acc_pub.verify_ex(self.data, signature, single=False, no_der=True)
        self.assertNotEqual(result, b'')

        # 验证非 DER 格式签名为 64 字节
        self.assertEqual(len(signature), 64)

    def test_single_hash_der(self):
        """测试单次 hash + DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=True, no_der=False)
        result = self.acc_pub.verify_ex(self.data, signature, single=True, no_der=False)
        self.assertNotEqual(result, b'')

        # 验证 DER 格式签名以 0x30 开头
        self.assertEqual(signature[0], 0x30)

    def test_single_hash_noder(self):
        """测试单次 hash + 非 DER 签名验签"""
        signature = self.acc_priv.sign_ex(self.data, single=True, no_der=True)
        result = self.acc_pub.verify_ex(self.data, signature, single=True, no_der=True)
        self.assertNotEqual(result, b'')

        # 验证非 DER 格式签名为 64 字节
        self.assertEqual(len(signature), 64)

    def test_wrong_parameters_fail(self):
        """测试签名验签参数不匹配时失败"""
        # 双次 hash 签名，单次 hash 验签
        signature = self.acc_priv.sign_ex(self.data, single=False, no_der=False)
        result = self.acc_pub.verify_ex(self.data, signature, single=True, no_der=False)
        self.assertEqual(result, b'')

        # DER 签名，非 DER 验签
        signature = self.acc_priv.sign_ex(self.data, single=False, no_der=False)
        result = self.acc_pub.verify_ex(self.data, signature, single=False, no_der=True)
        self.assertEqual(result, b'')

    def test_wrong_data_fail(self):
        """测试错误数据验签失败"""
        signature = self.acc_priv.sign(self.data)
        result = self.acc_pub.verify(b'wrong_data', signature)
        self.assertFalse(result)


class TestDumpLoadConfig(unittest.TestCase):
    """测试配置导入导出"""

    def test_dump_to_cfg(self):
        """测试导出配置"""
        acc = Address.generate()
        cfg = acc.dump_to_cfg()

        self.assertIsInstance(cfg, dict)
        self.assertIn('accounts', cfg)
        self.assertIn('default', cfg)

    def test_dump_to_cfg_with_passphrase(self):
        """测试带密码导出配置"""
        acc = Address.generate()
        cfg = acc.dump_to_cfg(passphrase='test123')

        # 验证私钥已加密
        fp = cfg['default']
        self.assertTrue(cfg['accounts'][fp]['encrypted'])

    def test_load_from_cfg(self):
        """测试从配置加载账户"""
        acc1 = Address.generate()
        cfg = acc1.dump_to_cfg(passphrase='test123')

        # 从配置加载
        fp = cfg['default']
        acc2 = Address.load_from_cfg(cfg['accounts'][fp],passphrase='test123')

        # 验证公钥相同
        self.assertEqual(acc1.publicKey(), acc2.publicKey())


if __name__ == '__main__':
    unittest.main()
