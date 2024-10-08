﻿using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// EC Diffie Hellman asymmetric algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class AsymmetricBcEcDiffieHellmanAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricBcEcDiffieHellmanPublicKey,
            AsymmetricBcEcDiffieHellmanPrivateKey,
            ECKeyPairGenerator,
            ECKeyGenerationParameters,
            ECDomainParameters,
            ECPublicKeyParameters,
            ECPrivateKeyParameters,
            AsymmetricBcEcDiffieHellmanAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "ECDH";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 521;
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
        public const string DISPLAY_NAME = "EC Diffie Hellman";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricBcEcDiffieHellmanAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            256,
            384,
            521
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricBcEcDiffieHellmanAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: true, _AllowedKeySizes, isPostQuantum: false, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        protected override ECKeyGenerationParameters CreateKeyGenParameters(SecureRandom random, ECDomainParameters parameters, CryptoOptions options)
            => new(parameters, random);

        /// <inheritdoc/>
        protected override ECDomainParameters GetEngineParameters(CryptoOptions options)
        {
            EnsureAllowedCurve(options.AsymmetricKeyBits);
            return BcEllipticCurves.GetCurve(options.AsymmetricKeyBits);
        }
    }
}
