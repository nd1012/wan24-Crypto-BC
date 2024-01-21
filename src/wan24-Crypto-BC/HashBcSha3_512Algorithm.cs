using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// SHA3-512 hash algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class HashBcSha3_512Algorithm : BouncyCastleHashAlgorithmBase<HashBcSha3_512Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SHA3-512";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 7;
        /// <summary>
        /// Hash length in bytes
        /// </summary>
        public const int HASH_LENGTH = 64;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = ALGORITHM_NAME;

        /// <summary>
        /// Constructor
        /// </summary>
        public HashBcSha3_512Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int HashLength => HASH_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override HashAlgorithm GetHashAlgorithmInt(CryptoOptions? options) => new BouncyCastleHashAlgorithm(new Sha3Digest(HASH_LENGTH << 3));
    }
}
