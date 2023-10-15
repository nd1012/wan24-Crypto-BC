using Org.BouncyCastle.Pqc.Crypto.Ntru;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// NTRUEncrypt asymmetric public key
    /// </summary>
    public sealed record class AsymmetricNtruEncryptPublicKey
        : BouncyCastleAsymmetricPublicKeyBase<AsymmetricNtruEncryptAlgorithm, NtruPublicKeyParameters, AsymmetricNtruEncryptPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricNtruEncryptPublicKey() : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricNtruEncryptPublicKey(byte[] keyData) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricNtruEncryptPublicKey(NtruPublicKeyParameters publicKey) : base(AsymmetricNtruEncryptAlgorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricNtruEncryptPublicKey(byte[] data) => Import<AsymmetricNtruEncryptPublicKey>(data);
    }
}
