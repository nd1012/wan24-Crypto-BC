using Org.BouncyCastle.Crypto.Parameters;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// X448 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricX448PublicKey
        : BouncyCastleAsymmetricNonPqcPublicKeyBase<AsymmetricX448Algorithm, X448PublicKeyParameters, AsymmetricX448PublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricX448PublicKey() : base(AsymmetricX448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricX448PublicKey(byte[] keyData) : base(AsymmetricX448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricX448PublicKey(X448PublicKeyParameters publicKey) : base(AsymmetricX448Algorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return 448;
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
        public static explicit operator AsymmetricX448PublicKey(byte[] data) => Import<AsymmetricX448PublicKey>(data);
    }
}
