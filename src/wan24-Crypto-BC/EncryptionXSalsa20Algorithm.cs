using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// XSalsa20 symmetric encryption algorithm (using 256 bit key)
    /// </summary>
    public sealed class EncryptionXSalsa20Algorithm : BouncyCastleStreamCipherAlgorithmBase<EncryptionXSalsa20Algorithm>
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "XSALSA20";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 2;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 24;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 1;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "XSalsa20";
        /// <summary>
        /// XSalsa20 raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_XSALSA20_RAW = "XSALSA20_RAW";

        /// <summary>
        /// Constructor
        /// </summary>
        public EncryptionXSalsa20Algorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

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
        protected override IStreamCipher CreateCipher(bool forEncryption, CryptoOptions options) => CreateXSalsa20(options);

        /// <summary>
        /// Create the XSalsa20 engine
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>ChaCha instance (not yet initialized)</returns>
        public static XSalsa20Engine CreateXSalsa20(CryptoOptions options)
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
