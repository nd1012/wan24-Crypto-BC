﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// HMAC-SHA3-256 MAC algorithm
    /// </summary>
    public sealed class MacHmacSha3_256Algorithm : BouncyCastleHmacAlgorithmBase<MacHmacSha3_256Algorithm>
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
        public MacHmacSha3_256Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int MacLength => MAC_LENGTH;

        /// <inheritdoc/>
        public override bool IsPostQuantum => false;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        protected override KeyedHashAlgorithm GetMacAlgorithmInt(byte[] pwd, CryptoOptions? options)
        {
            IMac mac = new HMac(new Sha3Digest(MAC_LENGTH << 3));
            mac.Init(new KeyParameter(pwd));
            return new BouncyCastleHmacAlgorithm(mac);
        }
    }
}
