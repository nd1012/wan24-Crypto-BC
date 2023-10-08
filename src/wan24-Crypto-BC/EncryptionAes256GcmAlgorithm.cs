using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// AES-256-GCM AEAD symmetric encryption algorithm (using 128 bit MAC)
    /// </summary>
    public sealed record class EncryptionAes256GcmAlgorithm : BouncyCastleAeadCipherAlgorithmBase<EncryptionAes256GcmAlgorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "AES256GCM";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 3;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 12;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 1;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "AES-256-GCM";
        /// <summary>
        /// AES-256-GCM raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_AES256GCM_RAW = "AES256GCM_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptionAes256GcmAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <inheritdoc/>
        public override int KeySize => KEY_SIZE;

        /// <inheritdoc/>
        public override int IvSize => IV_SIZE;

        /// <inheritdoc/>
        public override int BlockSize => BLOCK_SIZE;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => false;// Included in AEAD

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        /// <inheritdoc/>
        protected override IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options) => new BufferedAeadBlockCipher(new GcmBlockCipher(CreateAes(options)));

        /// <summary>
        /// Create the AES engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>AES instance (not yet initialized)</returns>
        public static AesEngine CreateAes(CryptoOptions options)
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
