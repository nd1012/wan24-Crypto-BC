using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.BC;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Compatibility_Tests
    {
        private static readonly byte[] TestData = [1, 2, 3];

        [TestMethod]
        public void EcDh_Tests()
        {
            using AsymmetricEcDiffieHellmanPrivateKey keyA = AsymmetricEcDiffieHellmanAlgorithm.Instance.CreateKeyPair();
            using AsymmetricBcEcDiffieHellmanPublicKey pubKeyA = new(keyA.PublicKey.KeyData.Array.CloneArray());
            using AsymmetricBcEcDiffieHellmanPrivateKey keyB = AsymmetricBcEcDiffieHellmanAlgorithm.Instance.CreateKeyPair();
            (byte[] secretB, byte[] kexB) = keyB.GetKeyExchangeData(pubKeyA);
            byte[] secretA = keyA.DeriveKey(kexB);
            Assert.IsTrue(secretA.SequenceEqual(secretB));
        }

        [TestMethod]
        public void EcDsa_Tests()
        {
            using AsymmetricEcDsaPrivateKey netKey = AsymmetricEcDsaAlgorithm.Instance.CreateKeyPair();
            using AsymmetricBcEcDsaPrivateKey bcKey = new(netKey.KeyData.Array);
            SignatureContainer signature = netKey.SignData(TestData);
            Assert.IsTrue(bcKey.PublicKey.ValidateSignature(signature, TestData, throwOnError: false), ".NET signature vlidation with Bouncy Castle failed");
            signature = bcKey.SignData(TestData);
            Assert.IsTrue(netKey.PublicKey.ValidateSignature(signature, TestData, throwOnError: false), "Bouncy Castle signature vlidation with .NET failed");
        }

        [TestMethod]
        public void Aes256Cbc_Tests()
        {
            CryptoOptions options = new()
            {
                LeaveOpen = true
            };
            using MemoryStream raw = new(TestData);
            using MemoryStream cipher = new();
            using MemoryStream decrypted = new();
            EncryptionAes256CbcAlgorithm.Instance.Encrypt(raw, cipher, TestData, options);
            cipher.Position = 0;
            EncryptionAes256CbcAlgorithm.Instance.Decrypt(cipher, decrypted, TestData, options);
            Assert.IsTrue(decrypted.ToArray().SequenceEqual(TestData));
        }

        [TestMethod]
        public void Sha3_Tests()
        {
            if (!Shake128.IsSupported) return;
            byte[] a, b;
            foreach (HashAlgorithmBase[] algos in new HashAlgorithmBase[][]{
                [HashSha3_256Algorithm.Instance, HashBcSha3_256Algorithm.Instance],
                [HashSha3_384Algorithm.Instance, HashBcSha3_384Algorithm.Instance],
                [HashSha3_512Algorithm.Instance, HashBcSha3_512Algorithm.Instance],
                })
            {
                a = algos[0].Hash(TestData);
                b = algos[1].Hash(TestData);
                Assert.IsTrue(a.SequenceEqual(b), $"{algos[0].GetType()} ({a.Length}/{b.Length})");
            }
            foreach (MacAlgorithmBase[] algos in new MacAlgorithmBase[][]{
                [MacHmacSha3_256Algorithm.Instance, MacBcHmacSha3_256Algorithm.Instance],
                [MacHmacSha3_384Algorithm.Instance, MacBcHmacSha3_384Algorithm.Instance],
                [MacHmacSha3_512Algorithm.Instance, MacBcHmacSha3_512Algorithm.Instance],
                })
            {
                a = algos[0].Mac(TestData, TestData);
                b = algos[1].Mac(TestData, TestData);
                Assert.IsTrue(a.SequenceEqual(b), $"{algos[0].GetType()} ({a.Length}/{b.Length})");
            }
        }
    }
}
