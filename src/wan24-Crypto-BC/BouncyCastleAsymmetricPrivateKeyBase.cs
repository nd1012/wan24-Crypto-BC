using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle asymmetric private key
    /// </summary>
    /// <typeparam name="tPublic">Public key type</typeparam>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tPrivateKey">Internal private key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract class BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal> : AsymmetricPrivateKeyBase<tPublic, tFinal>
        where tPublic : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey: AsymmetricKeyParameter
        where tFinal : BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal>, new()
    {
        /// <summary>
        /// Keys
        /// </summary>
        protected AsymmetricCipherKeyPair? Keys = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm, byte[] keyData) : this(algorithm) => KeyData = new(keyData);

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : this(algorithm)
        {
            try
            {
                Keys = keys;
                if (keys.Public is not tPublicKey) throw new ArgumentException("No valid public key parameters", nameof(keys));
                if (keys.Private is not tPrivateKey) throw new ArgumentException("No valid private key parameters", nameof(keys));
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
        public tPrivateKey PrivateKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys == null) DeserializeKeyData();
                    return (tPrivateKey)Keys!.Private;
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
        public sealed override tPublic PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys == null) throw new InvalidOperationException();
                    return _PublicKey ??= Activator.CreateInstance(typeof(tPublic), (tPublicKey)Keys.Public) as tPublic
                        ?? throw new InvalidProgramException($"Failed to instance {typeof(tPublic)}");
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
        public sealed override int Bits => PublicKey.Bits;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) { }//TODO Clear all keys

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        protected byte[] SerializeKeyData()
        {
            try
            {
                EnsureUndisposed();
                if (Keys == null) throw new InvalidOperationException();
                using MemoryStream ms = new();//TODO Use secure memory stream
                ms.WriteNumber(StreamSerializer.VERSION);
                byte[] keyInfo = PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((tPrivateKey)Keys.Private).PrivateKeyData.GetEncoded();
                try
                {
                    ms.WriteBytes(keyInfo);
                    keyInfo.Clear();
                    keyInfo = PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((tPublicKey)Keys.Public).GetEncoded();
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
        protected void DeserializeKeyData()
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
                    tPrivateKey privateKey = (tPrivateKey)PrivateKeyFactory.CreateKey(keyInfo);
                    keyInfo.Clear();
                    keyInfo = ms.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                    tPublicKey publicKey = (tPublicKey)PublicKeyFactory.CreateKey(keyInfo);
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
