using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Serpent 256 GCM symmetric encryption algorithm (using 128 bit MAC)
    /// </summary>
    public sealed record class EncryptionSerpent256GcmAlgorithm : BouncyCastleAeadCipherAlgorithmBase<EncryptionSerpent256GcmAlgorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "SERPENT256GCM";
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
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "Serpent 256 bit GCM";
        /// <summary>
        /// Serpent 256 GCM raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_SERPENT256GCM_RAW = "SERPENT256GCM_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionSerpent256GcmAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

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
        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        /// <inheritdoc/>
        protected override IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options) => new BufferedAeadBlockCipher(new GcmBlockCipher(CreateSerpent(options)));

        /// <summary>
        /// Create the Serpent engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Serpent instance (not yet initialized)</returns>
        public static SerpentEngine CreateSerpent(CryptoOptions options)
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
