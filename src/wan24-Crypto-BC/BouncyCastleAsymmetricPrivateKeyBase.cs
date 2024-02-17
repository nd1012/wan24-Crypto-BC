using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

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
    public abstract record class BouncyCastleAsymmetricPrivateKeyBase<tPublic, tAlgo, tPublicKey, tPrivateKey, tFinal> : AsymmetricPrivateKeyBase<tPublic, tFinal>
        where tPublic : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tPublic>, new()
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tPrivateKey : AsymmetricKeyParameter
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
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm, byte[] keyData) : base(algorithm)
        {
            KeyData = new(keyData);
            DeserializeKeyData();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keys">Keys</param>
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm, AsymmetricCipherKeyPair keys) : this(algorithm)
        {
            try
            {
                if (keys.Public is not tPublicKey) throw new ArgumentException("No valid public key parameters", nameof(keys));
                if (keys.Private is not tPrivateKey) throw new ArgumentException("No valid private key parameters", nameof(keys));
                Keys = keys;
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
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="privateKey">Private key</param>
        protected BouncyCastleAsymmetricPrivateKeyBase(string algorithm, tPrivateKey privateKey) : this(algorithm)
        {
            try
            {
                Keys = new(GetPublicKey(privateKey), privateKey);
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
        /// Is the key info export/import implemented in the Bouncy Castle library AND <c>wan24-Crypto-BC</c>?
        /// </summary>
        public static bool IsBcImportExportImplemented { get; } = true;

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
                    if (Keys is null) DeserializeKeyData();
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
        public override tPublic PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (Keys is null) throw new InvalidOperationException();
                    return _PublicKey ??= Activator.CreateInstance(typeof(tPublic), Keys.Public) as tPublic
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
        public override int Bits => PublicKey.Bits;

        /// <summary>
        /// Export the key in Bouncy Castle format, if possible
        /// </summary>
        /// <returns>Serialized key data (DER encoded; don't forget to clear!)</returns>
        public virtual byte[] ExportBc()
        {
            try
            {
                EnsureUndisposed();
                if (!IsBcImportExportImplemented) throw new NotSupportedException();
                if (Keys is null) throw new InvalidOperationException();
                return PrivateKeyInfoFactory.CreatePrivateKeyInfo(Keys.Private).GetDerEncoded();
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        protected abstract byte[] SerializeKeyData();

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        protected abstract void DeserializeKeyData();

        /// <summary>
        /// Serialize the full key data (private and public key)
        /// </summary>
        /// <returns>Serialized key data</returns>
        protected abstract byte[] SerializeFullKeyData();

        /// <summary>
        /// Deserialize the full key data (private and public key)
        /// </summary>
        protected abstract void DeserializeFullKeyData();

        /// <summary>
        /// Get the public key from a private key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <returns>Public key</returns>
        protected abstract tPublicKey GetPublicKey(tPrivateKey privateKey);

        /// <summary>
        /// Import a key in Bouncy Castle format (created by <see cref="ExportBc"/>)
        /// </summary>
        /// <param name="keyInfo">Serialized key data (created by <see cref="ExportBc"/>; won't be cleared)</param>
        /// <returns>Key (don't forget to dispose!)</returns>
        public static tFinal ImportBc(in byte[] keyInfo)
        {
            try
            {
                if (!IsBcImportExportImplemented) throw new NotSupportedException();
                return (tFinal)(Activator.CreateInstance(typeof(tFinal), PrivateKeyFactory.CreateKey(keyInfo) as tPrivateKey
                    ?? throw new InvalidDataException($"Failed to deserialize {typeof(tPrivateKey)} from the given key data"))
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}"));
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
