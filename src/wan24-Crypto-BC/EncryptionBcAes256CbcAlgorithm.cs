using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// AES-256-CBC symmetric encryption algorithm (using ISO10126 padding; may be used as replacement, if the .NET algorithm isn't available on the current platform)
    /// </summary>
    public sealed record class EncryptionBcAes256CbcAlgorithm : BouncyCastleBufferedCipherAlgorithmBase<EncryptionBcAes256CbcAlgorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "AES256CBC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
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
        public const string DISPLAY_NAME = "AES-256-CBC";

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionBcAes256CbcAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

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
        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        /// <inheritdoc/>
        protected override IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options)
            => new PaddedBufferedBlockCipher(new CbcBlockCipher(CreateAes(options)), new ISO10126d2Padding());

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
