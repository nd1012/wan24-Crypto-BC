using Org.BouncyCastle.Crypto.Parameters;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// X25519 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricX25519PublicKey
        : BouncyCastleAsymmetricNonPqcPublicKeyBase<AsymmetricX25519Algorithm, X25519PublicKeyParameters, AsymmetricX25519PublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricX25519PublicKey() : base(AsymmetricX25519Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricX25519PublicKey(byte[] keyData) : base(AsymmetricX25519Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricX25519PublicKey(X25519PublicKeyParameters publicKey) : base(AsymmetricX25519Algorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    return 256;
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
        public static explicit operator AsymmetricX25519PublicKey(byte[] data) => Import<AsymmetricX25519PublicKey>(data);
    }
}
