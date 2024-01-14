using Org.BouncyCastle.Crypto;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class fo a Bouncy Castle asymmetric public key
    /// </summary>
    /// <typeparam name="tAlgo">Algorithm type</typeparam>
    /// <typeparam name="tPublicKey">Internal public key type</typeparam>
    /// <typeparam name="tFinal">Final type</typeparam>
    public abstract record class BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tFinal> : AsymmetricPublicKeyBase
        where tAlgo : IAsymmetricAlgorithm, new()
        where tPublicKey : AsymmetricKeyParameter, ICipherParameters
        where tFinal : BouncyCastleAsymmetricPublicKeyBase<tAlgo, tPublicKey, tFinal>, new()
    {
        /// <summary>
        /// Public key
        /// </summary>
        protected tPublicKey? _PublicKey = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm) : base(algorithm) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="keyData">Key data</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm, byte[] keyData) : this(algorithm)
        {
            KeyData = new(keyData);
            DeserializeKeyData();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        /// <param name="publicKey">Public key</param>
        protected BouncyCastleAsymmetricPublicKeyBase(string algorithm, tPublicKey publicKey) : this(algorithm)
        {
            try
            {
                _PublicKey = publicKey;
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
        /// Public key
        /// </summary>
        public tPublicKey PublicKey
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey == null) DeserializeKeyData();
                    return _PublicKey!;
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
        public sealed override IAsymmetricPublicKey GetCopy()
        {
            try
            {
                EnsureUndisposed();
                return Activator.CreateInstance(typeof(tFinal), (byte[])KeyData.Array.Clone()) as IAsymmetricPublicKey
                    ?? throw new InvalidProgramException($"Failed to instance {typeof(tFinal)}");
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
    }
}
