using Org.BouncyCastle.Crypto;

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
        public override int Bits => PublicKey.Bits;

        /// <summary>
        /// Serialize the key data
        /// </summary>
        /// <returns>Serialized key data</returns>
        protected abstract byte[] SerializeKeyData();

        /// <summary>
        /// Deserialize the key data
        /// </summary>
        protected abstract void DeserializeKeyData();
    }
}
