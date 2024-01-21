using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Kyber asymmetric public key
    /// </summary>
    public sealed record class AsymmetricKyberPublicKey : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricKyberAlgorithm, KyberPublicKeyParameters, AsymmetricKyberPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricKyberPublicKey() : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricKyberPublicKey(byte[] keyData) : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricKyberPublicKey(KyberPublicKeyParameters publicKey) : base(AsymmetricKyberAlgorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricKyberPublicKey(byte[] data) => Import<AsymmetricKyberPublicKey>(data);
    }
}
