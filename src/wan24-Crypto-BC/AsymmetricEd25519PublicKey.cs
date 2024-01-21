using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed25519 asymmetric public key
    /// </summary>
    public sealed record class AsymmetricEd25519PublicKey
        : BouncyCastleAsymmetricNonPqcPublicSignatureKeyBase<AsymmetricEd25519Algorithm, Ed25519PublicKeyParameters, Ed25519Signer, AsymmetricEd25519PublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEd25519PublicKey() : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricEd25519PublicKey(byte[] keyData) : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricEd25519PublicKey(Ed25519PublicKeyParameters publicKey) : base(AsymmetricEd25519Algorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricEd25519PublicKey(byte[] data) => Import<AsymmetricEd25519PublicKey>(data);
    }
}
