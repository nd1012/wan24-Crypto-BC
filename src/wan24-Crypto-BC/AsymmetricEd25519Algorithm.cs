using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed25519 asymmetric algorithm (128 bit security)
    /// </summary>
    public sealed record class AsymmetricEd25519Algorithm
         : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricEd25519PublicKey,
            AsymmetricEd25519PrivateKey,
            Ed25519KeyPairGenerator,
            Ed25519KeyGenerationParameters,
            AsymmetricKeyParameter,
            Ed25519PublicKeyParameters,
            Ed25519PrivateKeyParameters,
            AsymmetricEd25519Algorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ED25519";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 8;
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
        public const string DISPLAY_NAME = "Ed25519";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricEd25519Algorithm() => _AllowedKeySizes = new List<int>()
        {
            256
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricEd25519Algorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override AsymmetricEd25519PrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                Ed25519KeyPairGenerator keyGen = new();
                keyGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance())));
                return new(keyGen.GenerateKeyPair());
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
        protected override AsymmetricKeyParameter GetEngineParameters(CryptoOptions options) => throw new NotSupportedException();
    }
}
