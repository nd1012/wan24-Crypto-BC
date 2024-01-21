using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Shake128 hash algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class HashBcShake128Algorithm : BouncyCastleHashAlgorithmBase<HashBcShake128Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHAKE128";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 8;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Shake128";

        /// <summary>
        /// Constructor
        /// </summary>
        public HashBcShake128Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => new BouncyCastleHashAlgorithm(new ShakeDigest(128));
    }
}
