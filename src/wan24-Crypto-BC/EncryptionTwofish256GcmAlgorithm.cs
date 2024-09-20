using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Twofish 256 GCM symmetric encryption algorithm (using 128 bit MAC)
    /// </summary>
    public sealed record class EncryptionTwofish256GcmAlgorithm : BouncyCastleAeadCipherAlgorithmBase<EncryptionTwofish256GcmAlgorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "TWOFISH256GCM";
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
        public const long MAX_CIPHER_DATA_LENGTH = 274_877_906_944;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = 10_000_000;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Twofish 256 bit GCM";
        /// <summary>
        /// Twofish 256 GCM raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_TWOFISH256GCM_RAW = "TWOFISH256GCM_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionTwofish256GcmAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int KeySize => KEY_SIZE;

        /// <inheritdoc/>
        public override int IvSize => IV_SIZE;

        /// <inheritdoc/>
        public override int BlockSize => BLOCK_SIZE;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => false;

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
            => new BufferedAeadBlockCipher(new GcmBlockCipher(CreateTwofish(options)));

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
