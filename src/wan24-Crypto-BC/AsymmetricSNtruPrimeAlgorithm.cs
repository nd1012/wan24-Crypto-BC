using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Streamlined NTRU Prime asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricSNtruPrimeAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricSNtruPrimePublicKey,
            AsymmetricSNtruPrimePrivateKey,
            SNtruPrimeKeyGenerationParameters,
            SNtruPrimeParameters,
            SNtruPrimePublicKeyParameters,
            SNtruPrimePrivateKeyParameters,
            AsymmetricSNtruPrimeAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SNTRUP";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 14;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 1277;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = long.MaxValue;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.KeyExchange;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Streamlined NTRU Prime";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricSNtruPrimeAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            653,// 128 bit security
            761,// 153 bit security
            857,// 175 bit security
            953,// 196 bit security
            1013,// 209 bit security
            1277// 270 bit security
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricSNtruPrimeAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => false;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        public override AsymmetricSNtruPrimePrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                EnsureAllowed();
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                SNtruPrimeKeyPairGenerator keyGen = new();
                keyGen.Init(CreateKeyGenParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance()), GetEngineParameters(options), options));
                return Activator.CreateInstance(typeof(AsymmetricSNtruPrimePrivateKey), keyGen.GenerateKeyPair()) as AsymmetricSNtruPrimePrivateKey
                    ?? throw new InvalidProgramException($"Failed to instance asymmetric private key {typeof(AsymmetricSNtruPrimePrivateKey)}");
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

        /// <inheritdoc/>
        protected override SNtruPrimeParameters GetEngineParameters(CryptoOptions options) => AsymmetricSNtruPrimeHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
