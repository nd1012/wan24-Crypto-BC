using Org.BouncyCastle.Crypto.Parameters;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// EC Diffie Hellman asymmetric public key
    /// </summary>
    public sealed record class AsymmetricBcEcDiffieHellmanPublicKey
        : BouncyCastleAsymmetricNonPqcPublicKeyBase<AsymmetricBcEcDiffieHellmanAlgorithm, ECPublicKeyParameters, AsymmetricBcEcDiffieHellmanPublicKey>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricBcEcDiffieHellmanPublicKey() : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keyData">Key data</param>
        public AsymmetricBcEcDiffieHellmanPublicKey(byte[] keyData) : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME, keyData) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key</param>
        public AsymmetricBcEcDiffieHellmanPublicKey(ECPublicKeyParameters publicKey) : base(AsymmetricBcEcDiffieHellmanAlgorithm.ALGORITHM_NAME, publicKey) { }

        /// <inheritdoc/>
        public override int Bits
        {
            get
            {
                try
                {
                    EnsureUndisposed();
                    if(_PublicKey is null) throw new InvalidOperationException();
                    return BcEllipticCurves.GetKeySize(_PublicKey.Parameters);
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
        public static explicit operator AsymmetricBcEcDiffieHellmanPublicKey(byte[] data) => Import<AsymmetricBcEcDiffieHellmanPublicKey>(data);
    }
}
