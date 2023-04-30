using Org.BouncyCastle.Pqc.Crypto.Falcon;
using System.Collections.ObjectModel;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FALCON asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricFalconAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricFalconPublicKey, 
            AsymmetricFalconPrivateKey, 
            FalconKeyPairGenerator, 
            FalconKeyGenerationParameters, 
            FalconParameters, 
            FalconPublicKeyParameters, 
            FalconPrivateKeyParameters, 
            AsymmetricFalconAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "FALCON";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 4;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 1024;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricFalconAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            512,
            1024
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricFalconAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        protected override FalconParameters GetEngineParameters(CryptoOptions options) => AsymmetricFalconHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
