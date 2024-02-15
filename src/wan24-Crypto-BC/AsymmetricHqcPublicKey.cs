using Org.BouncyCastle.Pqc.Crypto.Hqc;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HQC asymmetric public key
    /// </summary>
    public sealed record class AsymmetricHqcPublicKey : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricHqcAlgorithm, HqcPublicKeyParameters, AsymmetricHqcPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricHqcPublicKey() : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricHqcPublicKey(byte[] keyData) : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricHqcPublicKey(HqcPublicKeyParameters publicKey) : base(AsymmetricHqcAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        new public static bool IsBcImportExportImplemented => false;

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if (_PublicKey is null) throw new InvalidOperationException();
                    return AsymmetricHqcHelper.GetKeySize(_PublicKey.Parameters);
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
        public static explicit operator AsymmetricHqcPublicKey(byte[] data) => Import<AsymmetricHqcPublicKey>(data);
    }
}
