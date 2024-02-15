using Org.BouncyCastle.Pqc.Crypto.Picnic;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Picnic asymmetric public key
    /// </summary>
    public sealed record class AsymmetricPicnicPublicKey
        : BouncyCastleAsymmetricPqcPublicSignatureKeyBase<AsymmetricPicnicAlgorithm, PicnicPublicKeyParameters, PicnicSigner, AsymmetricPicnicPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricPicnicPublicKey() : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricPicnicPublicKey(byte[] keyData) : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricPicnicPublicKey(PicnicPublicKeyParameters publicKey) : base(AsymmetricPicnicAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is null) throw new InvalidOperationException();
                    return AsymmetricPicnicHelper.GetKeySize(_PublicKey.Parameters);
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
        public static explicit operator AsymmetricPicnicPublicKey(byte[] data) => Import<AsymmetricPicnicPublicKey>(data);
    }
}
