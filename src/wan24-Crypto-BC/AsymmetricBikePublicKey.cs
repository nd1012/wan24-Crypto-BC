using Org.BouncyCastle.Pqc.Crypto.Bike;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// BIKE asymmetric public key
    /// </summary>
    public sealed record class AsymmetricBikePublicKey : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricBikeAlgorithm, BikePublicKeyParameters, AsymmetricBikePublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBikePublicKey() : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBikePublicKey(byte[] keyData) : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricBikePublicKey(BikePublicKeyParameters publicKey) : base(AsymmetricBikeAlgorithm.ALGORITHM_NAME, publicKey) { }

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
                    return AsymmetricBikeHelper.GetKeySize(_PublicKey.Parameters);
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
        public static explicit operator AsymmetricBikePublicKey(byte[] data) => Import<AsymmetricBikePublicKey>(data);
    }
}
