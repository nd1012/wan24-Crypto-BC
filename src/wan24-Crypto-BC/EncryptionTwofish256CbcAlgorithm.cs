using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Twofish 256 CBC symmetric encryption algorithm (using ISO10126 padding)
    /// </summary>
    public sealed record class EncryptionTwofish256CbcAlgorithm : BouncyCastleBufferedCipherAlgorithmBase<EncryptionTwofish256CbcAlgorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "TWOFISH256CBC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 6;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 16;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 16;
        /// <summary>
        /// Maximum cipher data length in bytes
        /// </summary>
        public const long MAX_CIPHER_DATA_LENGTH = 140_737_488_355_328;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = 65_000_000;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Twofish 256 bit CBC";
        /// <summary>
        /// Twofish 256 CBC raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_TWOFISH256CBC_RAW = "TWOFISH256CBC_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionTwofish256CbcAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int KeySize => KEY_SIZE;

        /// <inheritdoc/>
        public override int IvSize => IV_SIZE;

        /// <inheritdoc/>
        public override int BlockSize => BLOCK_SIZE;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => true;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override long MaxCipherDataLength => MAX_CIPHER_DATA_LENGTH;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        /// <inheritdoc/>
        protected override IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options)
            => new PaddedBufferedBlockCipher(new CbcBlockCipher(CreateTwofish(options)), new ISO10126d2Padding());

        /// <inheritdoc/>
        protected override ICipherParameters CreateParameters(byte[] iv, CryptoOptions options) => CreateKeyParameters(iv, options, HashBcSha3_256Algorithm.Instance);

        /// <summary>
        /// Create the Twofish engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Twofish instance (not yet initialized)</returns>
        public static TwofishEngine CreateTwofish(CryptoOptions options)
        {
            EncryptionHelper.GetDefaultOptions(options);
            try
            {
                return new();
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
    }
}
