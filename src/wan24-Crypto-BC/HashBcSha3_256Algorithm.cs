﻿using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SHA3-256 hash algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class HashBcSha3_256Algorithm : BouncyCastleHashAlgorithmBase<HashBcSha3_256Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA3-256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 5;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = ALGORITHM_NAME;

        /// <summary>
        /// Constructor
        /// </summary>
        private HashBcSha3_256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => new SHA3_256();

        /// <summary>
        /// SHA3-256
        /// </summary>
        public sealed class SHA3_256() : BouncyCastleHashAlgorithm(new Sha3Digest(HASH_LENGTH << 3))
        {
            /// <summary>
            /// Register to the <see cref="CryptoConfig"/>
            /// </summary>
            public static void Register() => CryptoConfig.AddAlgorithm(typeof(SHA3_256), ALGORITHM_NAME);
        }
    }
}
