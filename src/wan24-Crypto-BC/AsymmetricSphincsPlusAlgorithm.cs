using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using System.Collections.ObjectModel;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricSphincsPlusAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricSphincsPlusPublicKey, 
            AsymmetricSphincsPlusPrivateKey, 
            SphincsPlusKeyPairGenerator, 
            SphincsPlusKeyGenerationParameters, 
            SphincsPlusParameters, 
            SphincsPlusPublicKeyParameters, 
            SphincsPlusPrivateKeyParameters, 
            AsymmetricSphincsPlusAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SPHINCSPLUS";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 5;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "SPHINCS+";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricSphincsPlusAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,
            192,
            256
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSphincsPlusAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override SphincsPlusParameters GetEngineParameters(CryptoOptions options) => AsymmetricSphincsPlusHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
