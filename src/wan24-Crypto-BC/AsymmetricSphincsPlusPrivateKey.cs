using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric private key
    /// </summary>
    public sealed class AsymmetricSphincsPlusPrivateKey : AsymmetricPrivateKeyBase<AsymmetricSphincsPlusPublicKey, AsymmetricSphincsPlusPrivateKey>, ISignaturePrivateKey
    {
        /// <summary>
        /// Keys
        /// </summary>
        private AsymmetricCipherKeyPair? Keys = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusPrivateKey() : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSphincsPlusPrivateKey(byte[] keyData) : this() => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keys">Keys</param>
        public AsymmetricSphincsPlusPrivateKey(AsymmetricCipherKeyPair keys) : this()
        {
            try
            {
                Keys = keys;
                if (keys.Public is not SphincsPlusPublicKeyParameters) throw new ArgumentException("No SPHINCS+ public key parameters", nameof(keys));
                if (keys.Private is not SphincsPlusPrivateKeyParameters) throw new ArgumentException("No SPHINCS+ private key parameters", nameof(keys));
                KeyData = new(SerializeKeyData());
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

        /// <summary>
        /// Private key
        /// </summary>
        public SphincsPlusPrivateKeyParameters PrivateKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys == null) DeserializeKeyData();
                    return (SphincsPlusPrivateKeyParameters)Keys!.Private;
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
        }

        /// <inheritdoc/>
        public override AsymmetricSphincsPlusPublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys == null) throw new InvalidOperationException();
                    return _PublicKey ??= new((SphincsPlusPublicKeyParameters)Keys.Public);
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
        }

        /// <inheritdoc/>
        public override byte[] SignHashRaw(byte[] hash)
        {
            try
            {
                EnsureUndisposed();
                SphincsPlusSigner signer = new();
                signer.Init(forSigning: true, PrivateKey);
                return signer.GenerateSignature(hash);
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        public override int Bits => PublicKey.Bits;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) { }//TODO Clear all keys

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        private byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (Keys == null) throw new InvalidOperationException();
                using MemoryStream ms = new();//TODO Use secure memory stream
                ms.WriteNumber(StreamSerializer.VERSION);
                byte[] keyInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((SphincsPlusPrivateKeyParameters)Keys.Private).PrivateKeyData.GetEncoded();
                try
                {
                    ms.WriteBytes(keyInfo);
                    keyInfo.Clear();
                    keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((SphincsPlusPublicKeyParameters)Keys.Public).GetEncoded();
                    ms.WriteBytes(keyInfo);
                    keyInfo.Clear();
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
                }
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

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        private void DeserializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                using MemoryStream ms = new(KeyData.Array);//TODO Use secure memory stream
                int serializerVersion = ms.ReadNumber<int>();
                if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new SerializerException($"Invalid serializer version {serializerVersion}");
                byte[] keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                try
                {
                    SphincsPlusPrivateKeyParameters privateKey = (SphincsPlusPrivateKeyParameters)PrivateKeyFactory.CreateKey(keyInfo);
                    keyInfo.Clear();
                    keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                    SphincsPlusPublicKeyParameters publicKey = (SphincsPlusPublicKeyParameters)PublicKeyFactory.CreateKey(keyInfo);
                    keyInfo.Clear();
                    Keys = new(publicKey, privateKey);
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    keyInfo.Clear();
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
    }
}
