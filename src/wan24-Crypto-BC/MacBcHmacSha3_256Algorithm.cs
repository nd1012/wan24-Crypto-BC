using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HMAC-SHA3-256 MAC algorithm (may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class MacBcHmacSha3_256Algorithm : BouncyCastleHmacAlgorithmBase<MacBcHmacSha3_256Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "HMAC-SHA3-256";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 4;
        /// <summary>
        /// MAC length in bytes
        /// </summary>
        public const int MAC_LENGTH = 32;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "HMAC SHA3-256";

        /// <summary>
        /// Constructor
        /// </summary>
        private MacBcHmacSha3_256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options) => new HMACSHA3_256(pwd);

        /// <summary>
        /// HMACSHA3-256
        /// </summary>
        public sealed class HMACSHA3_256 : BouncyCastleHmacAlgorithm
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="pwd">Password</param>
            public HMACSHA3_256(byte[] pwd) : base(new HMac(new Sha3Digest(MAC_LENGTH << 3))) => Mac.Init(new KeyParameter(pwd));

            /// <summary>
            /// Register to the <see cref="CryptoConfig"/>
            /// </summary>
            public static void Register() => CryptoConfig.AddAlgorithm(typeof(HMACSHA3_256), "HMACSHA3-256");
        }
    }
}
