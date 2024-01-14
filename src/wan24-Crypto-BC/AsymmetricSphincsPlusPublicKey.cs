using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric public key
    /// </summary>
    public sealed record class AsymmetricSphincsPlusPublicKey
        : BouncyCastleAsymmetricPqcPublicSignatureKeyBase<AsymmetricSphincsPlusAlgorithm,  SphincsPlusPublicKeyParameters, SphincsPlusSigner, AsymmetricSphincsPlusPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusPublicKey() : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricSphincsPlusPublicKey(byte[] keyData) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricSphincsPlusPublicKey(SphincsPlusPublicKeyParameters publicKey) : base(AsymmetricSphincsPlusAlgorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricSphincsPlusPublicKey(byte[] data) => Import<AsymmetricSphincsPlusPublicKey>(data);
    }
}
