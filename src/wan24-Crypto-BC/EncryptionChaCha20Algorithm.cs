using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// ChaCha20 symmetric encryption algorithm (using 256 bit key)
    /// </summary>
    public sealed class EncryptionChaCha20Algorithm : BouncyCastleStreamCipherAlgorithmBase<EncryptionChaCha20Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "CHACHA20";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 1;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 8;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 1;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "ChaCha20";
        /// <summary>
        /// ChaCha20 raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_CHACHA20_RAW = "CHACHA20_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptionChaCha20Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

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
        protected override IStreamCipher CreateCipher(bool forEncryption, CryptoOptions options) => CreateChaCha(options);

        /// <summary>
        /// Create the ChaCha engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>ChaCha instance (not yet initialized)</returns>
        public static ChaChaEngine CreateChaCha(CryptoOptions options)
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
