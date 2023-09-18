using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle AEAD stream cipher
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract class BouncyCastleAeadStreamCipherAlgorithmBase<T> : EncryptionAlgorithmBase where T : BouncyCastleAeadStreamCipherAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleAeadStreamCipherAlgorithmBase() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Agorithm value</param>
        protected BouncyCastleAeadStreamCipherAlgorithmBase(string name, int value) : base(name, value) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static T Instance { get; }

        /// <inheritdoc/>
        protected sealed override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                IAeadBlockCipher cipher = CreateCipher(forEncryption: true, options);
                byte[] iv = CreateIvBytes();
                cipher.Init(forEncryption: true, CreateParameters(iv, options));
                cipherData.Write(iv);
                return new BouncyCastleCryptoTransform(cipher);
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

        /// <inheritdoc/>
        protected sealed override async Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                IAeadBlockCipher cipher = CreateCipher(forEncryption: true, options);
                byte[] iv = CreateIvBytes();
                cipher.Init(forEncryption: true, CreateParameters(iv, options));
                await cipherData.WriteAsync(iv, cancellationToken).DynamicContext();
                return new BouncyCastleCryptoTransform(cipher);
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

        /// <inheritdoc/>
        protected sealed override ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                byte[] iv = ReadFixedIvBytes(cipherData, options);
                IAeadBlockCipher cipher = CreateCipher(forEncryption: false, options);
                cipher.Init(forEncryption: false, CreateParameters(iv, options));
                return new BouncyCastleCryptoTransform(cipher);
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

        /// <inheritdoc/>
        protected sealed override async Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                byte[] iv = await ReadFixedIvBytesAsync(cipherData, options, cancellationToken).DynamicContext();
                IAeadBlockCipher cipher = CreateCipher(forEncryption: false, options);
                cipher.Init(forEncryption: false, CreateParameters(iv, options));
                return new BouncyCastleCryptoTransform(cipher);
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

        /// <summary>
        /// Create the cipher engine
        /// </summary>
        /// <param name="forEncryption">For encryption?</param>
        /// <param name="options">Options</param>
        /// <returns>Stream cipher</returns>
        protected abstract IAeadBlockCipher CreateCipher(bool forEncryption, CryptoOptions options);

        /// <summary>
        /// Create cipher parameters
        /// </summary>
        /// <param name="iv">IV bytes</param>
        /// <param name="options">Options</param>
        /// <returns>Parameters</returns>
        protected virtual ICipherParameters CreateParameters(byte[] iv, CryptoOptions options)
            => new AeadParameters(new KeyParameter(options.Password ?? throw new ArgumentException("Missing password", nameof(options))), macSize: 128, iv);

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(T), Instance.Name);
    }
}
