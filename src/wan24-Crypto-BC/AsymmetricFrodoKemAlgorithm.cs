﻿using Org.BouncyCastle.Pqc.Crypto.Frodo;
using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// FrodoKEM asymmetric algorithm
    /// </summary>
    public sealed record class AsymmetricFrodoKemAlgorithm
        : BouncyCastleAsymmetricAlgorithmBase<
            AsymmetricFrodoKemPublicKey,
            AsymmetricFrodoKemPrivateKey,
            FrodoKeyPairGenerator,
            FrodoKeyGenerationParameters,
            FrodoParameters,
            FrodoPublicKeyParameters,
            FrodoPrivateKeyParameters,
            AsymmetricFrodoKemAlgorithm
            >
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "FRODOKEM";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 6;
        /// <summary>
        /// Default key size in bits
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 256;
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
        public const string DISPLAY_NAME = "FrodoKEM";

        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        private static readonly FrozenSet<int> _AllowedKeySizes;

        /// <summary>
        /// Static constructor
        /// </summary>
        static AsymmetricFrodoKemAlgorithm() => _AllowedKeySizes = new List<int>()
        {
            128,
            192,
            256
        }.ToFrozenSet();

        /// <summary>
        /// Constructor
        /// </summary>
        private AsymmetricFrodoKemAlgorithm()
            : base(ALGORITHM_NAME, ALGORITHM_VALUE, USAGES, isEllipticCurveAlgorithm: false, _AllowedKeySizes, isPostQuantum: true, DEFAULT_KEY_SIZE)
        { }

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsPublicKeyStandardFormat => true;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        protected override FrodoParameters GetEngineParameters(CryptoOptions options) => AsymmetricFrodoKemHelper.GetParameters(options.AsymmetricKeyBits);
    }
}
