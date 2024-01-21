using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed448 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricEd448PublicKey
        : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase2<AsymmetricEd448Algorithm, Ed448PublicKeyParameters, Ed448Signer, AsymmetricEd448PublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEd448PublicKey() : base(AsymmetricEd448Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricEd448PublicKey(byte[] keyData) : base(AsymmetricEd448Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricEd448PublicKey(Ed448PublicKeyParameters publicKey) : base(AsymmetricEd448Algorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricEd448PublicKey(byte[] data) => Import<AsymmetricEd448PublicKey>(data);
    }
}
