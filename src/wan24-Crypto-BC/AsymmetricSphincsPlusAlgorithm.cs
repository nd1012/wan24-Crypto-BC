using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SPHINCS+ asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricSphincsPlusAlgorithm
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
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricSphincsPlusAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,// 128 bit security
            192,// 192 bit security
            256// 256 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricSphincsPlusAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => false;

        /// <inheritdoc/>
        protected override SphincsPlusParameters GetEngineParameters(CryptoOptions options) => AsymmetricSphincsPlusHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
