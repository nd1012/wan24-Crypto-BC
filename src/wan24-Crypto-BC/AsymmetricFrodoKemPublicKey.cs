using Org.BouncyCastle.Pqc.Crypto.Frodo;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEM asymmetric public key
    /// </summary>
    public sealed record class AsymmetricFrodoKemPublicKey : BouncyCastleAsymmetricPqcPublicKeyBase<AsymmetricFrodoKemAlgorithm, FrodoPublicKeyParameters, AsymmetricFrodoKemPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFrodoKemPublicKey() : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricFrodoKemPublicKey(byte[] keyData) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricFrodoKemPublicKey(FrodoPublicKeyParameters publicKey) : base(AsymmetricFrodoKemAlgorithm.ALGORITHM_NAME, publicKey) { }

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
        public static explicit operator AsymmetricFrodoKemPublicKey(byte[] data) => Import<AsymmetricFrodoKemPublicKey>(data);
    }
}
