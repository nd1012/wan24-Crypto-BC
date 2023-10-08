using Org.BouncyCastle.Pqc.Crypto.Falcon;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Asymmetric FALCON public key
    /// </summary>
    public sealed record class AsymmetricFalconPublicKey : BouncyCastleAsymmetricPublicSignatureKeyBase<AsymmetricFalconAlgorithm, FalconPublicKeyParameters, FalconSigner, AsymmetricFalconPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFalconPublicKey() : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFalconPublicKey(byte[] keyData) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricFalconPublicKey(FalconPublicKeyParameters publicKey) : base(AsymmetricFalconAlgorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricFalconPublicKey(byte[] data) => Import<AsymmetricFalconPublicKey>(data);
    }
}
