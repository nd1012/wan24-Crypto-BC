using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.ObjectModel;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Ed448 asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricEd448Algorithm
         : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricEd448PublicKey,
            AsymmetricEd448PrivateKey,
            Ed448KeyPairGenerator,
            Ed448KeyGenerationParameters,
            AsymmetricKeyParameter,
            Ed448PublicKeyParameters,
            Ed448PrivateKeyParameters,
            AsymmetricEd448Algorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ED448";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 9;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 456;
        /// <summary>
        /// Algorithm usages
        /// </summary>
        public const AsymmetricAlgorithmUsages USAGES = AsymmetricAlgorithmUsages.Signature;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "edwards448-Goldilocks";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly ReadOnlyCollection<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricEd448Algorithm() => _AllowedKeySizes = new List<int>()
        {
            448,
            456
        }.AsReadOnly();

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricEd448Algorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }


        /// <inheritdoc/>
        public override AsymmetricEd448PrivateKey CreateKeyPair(CryptoOptions? options = null)
        {
            try
            {
                options ??= DefaultOptions;
                options = AsymmetricHelper.GetDefaultKeyExchangeOptions(options);
                if (!options.AsymmetricKeyBits.In(AllowedKeySizes)) throw new ArgumentException("Invalid key size", nameof(options));
                Ed448KeyPairGenerator keyGen = new();
                keyGen.Init(new Ed448KeyGenerationParameters(new SecureRandom(BouncyCastleRandomGenerator.Instance())));
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
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override AsymmetricKeyParameter GetEngineParameters(CryptoOptions options) => throw new NotSupportedException();
    }
}
