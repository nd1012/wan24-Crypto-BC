using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric public key
    /// </summary>
    public sealed class AsymmetricDilithiumPublicKey
        : BouncyCastleAsymmetricPublicSignatureKeyBase<AsymmetricDilithiumAlgorithm, DilithiumPublicKeyParameters, DilithiumSigner, AsymmetricDilithiumPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricDilithiumPublicKey() : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricDilithiumPublicKey(byte[] keyData) : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricDilithiumPublicKey(DilithiumPublicKeyParameters publicKey) : base(AsymmetricDilithiumAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return _PublicKey?.Parameters.GetKeySize() ?? throw new InvalidOperationException();
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

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricDilithiumPublicKey(byte[] data) => Import<AsymmetricDilithiumPublicKey>(data);
    }
}
