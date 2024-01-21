using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HMAC-SHA3-384 MAC algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class MacBcHmacSha3_384Algorithm : BouncyCastleHmacAlgorithmBase<MacBcHmacSha3_384Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA3-384";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 5;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 48;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA3-384";

        /// <summary>
        /// Constructor
        /// </summary>
        public MacBcHmacSha3_384Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options)
        {
            HMac mac = new(new Sha3Digest(MAC_LENGTH << 3));
            mac.Init(new KeyParameter(pwd));
            return new BouncyCastleHmacAlgorithm(mac);
        }
    }
}
