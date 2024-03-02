using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// EC DSA asymmetric algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class AsymmetricBcEcDsaAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricBcEcDsaPublicKey,
            AsymmetricBcEcDsaPrivateKey,
            ECKeyPairGenerator,
            ECKeyGenerationParameters,
            ECDomainParameters,
            ECPublicKeyParameters,
            ECPrivateKeyParameters,
            AsymmetricBcEcDsaAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ECDSA";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 1;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 521;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "EC DSA";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricBcEcDsaAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            256,
            384,
            521
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricBcEcDsaAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        protected override ECKeyGenerationParameters CreateKeyGenParameters(SecureRandom random, ECDomainParameters parameters, CryptoOptions options)
            => new(parameters, random);

        /// <inheritdoc/>
        protected override ECDomainParameters GetEngineParameters(CryptoOptions options) => BcEllipticCurves.GetCurve(options.AsymmetricKeyBits);
    }
}
