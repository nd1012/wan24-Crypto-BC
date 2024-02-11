using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEM asymmetric private key
    /// </summary>
    public sealed record class AsymmetricFrodoKemPrivateKey
        : BouncyCastleAsymmetricPqcPrivateKeyExchangeKeyBase<
            AsymmetricFrodoKemPublicKey, 
            AsymmetricFrodoKemAlgorithm, 
            FrodoPublicKeyParameters, 
            FrodoPrivateKeyParameters, 
            FrodoKEMGenerator, 
            FrodoKEMExtractor, 
            AsymmetricFrodoKemPrivateKey
            >
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFrodoKemPrivateKey() : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFrodoKemPrivateKey(byte[] keyData) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricFrodoKemPrivateKey(AsymmetricCipherKeyPair keys) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, keys) { }

        /// <inheritdoc/>
        protected override byte[] SerializeKeyData()
        {
            // Custom serialization required, because there seems to be no way to derive the public key from the private key
            try
            {
                EnsureUndisposed();
                if (Keys == null) throw new InvalidOperationException();
                using MemoryPoolStream ms = new()
                {
                    CleanReturned = true
                };
                PrivateKeyInfo privateKeyInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private);
                using SecureByteArray privateKey = new(privateKeyInfo.GetDerEncoded());
                SubjectPublicKeyInfo publicKeyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Keys.Public);
                using SecureByteArray publicKey = new(publicKeyInfo.GetDerEncoded());
                ms.WriteSerializerVersion()
                    .WriteBytes(privateKey.Array)
                    .WriteBytes(publicKey.Array);
                return ms.ToArray();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                FrodoPrivateKeyParameters? privateKey = null;
                FrodoPublicKeyParameters? publicKey = null;
                try
                {
                    using MemoryStream ms = new(KeyData.Array);
                    int ssv = ms.ReadSerializerVersion();
                    using SecureByteArrayRefStruct privateKeyInfo = new(ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
                    privateKey = PqcPrivateKeyFactory.CreateKey(privateKeyInfo.Array) as FrodoPrivateKeyParameters ?? throw new InvalidDataException("Invalid private FrodoKEM key");
                    using SecureByteArrayRefStruct publicKeyInfo = new(ms.ReadBytes(ssv, maxLen: ushort.MaxValue).Value);
                    publicKey = PqcPublicKeyFactory.CreateKey(publicKeyInfo.Array) as FrodoPublicKeyParameters ?? throw new InvalidDataException("Invalid public FrodoKEM key");
                    Keys = new(publicKey, privateKey);
                }
                catch
                {
                    privateKey?.ClearPrivateByteArrayFields();
                    publicKey?.ClearPrivateByteArrayFields();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override FrodoPublicKeyParameters GetPublicKey(FrodoPrivateKeyParameters privateKey) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Keys?.Private.ClearPrivateByteArrayFields();//TODO All parameter fields are private :(
        }

        /// <summary>
        /// Cast to public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator AsymmetricFrodoKemPublicKey(AsymmetricFrodoKemPrivateKey privateKey) => privateKey.PublicKey;

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricFrodoKemPrivateKey(byte[] data) => Import<AsymmetricFrodoKemPrivateKey>(data);
    }
}
