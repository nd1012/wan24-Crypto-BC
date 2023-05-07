using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using System.Collections.ObjectModel;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// CRYSTALS-Dilithium asymmetric algorithm
    /// </summary>
    public sealed class AsymmetricDilithiumAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricDilithiumPublicKey,
            AsymmetricDilithiumPrivateKey,
            DilithiumKeyPairGenerator,
            DilithiumKeyGenerationParameters,
            DilithiumParameters,
            DilithiumPublicKeyParameters,
            DilithiumPrivateKeyParameters,
            AsymmetricDilithiumAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "CRYSTALSDILITHIUM";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 3;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 1024;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "CRYSTALS-Dilithium";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricDilithiumAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            512,
            768,
            1024
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricDilithiumAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override DilithiumParameters GetEngineParameters(CryptoOptions options) => AsymmetricDilithiumHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
