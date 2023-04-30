using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle block cipher
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract class BouncyCastleBlockCipherAlgorithmBase<T> : EncryptionAlgorithmBase where T : BouncyCastleBlockCipherAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleBlockCipherAlgorithmBase() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Agorithm value</param>
        protected BouncyCastleBlockCipherAlgorithmBase(string name, int value) : base(name, value) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static T Instance { get; }

        /// <inheritdoc/>
        protected sealed override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                IBlockCipher cipher = CreateCipher(forEncryption: true, options);
                byte[] iv = CreateIvBytes();
                cipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(options.Password ?? throw new ArgumentException("Missing password", nameof(options))), iv));
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
                IBlockCipher cipher = CreateCipher(forEncryption: true, options);
                byte[] iv = CreateIvBytes();
                cipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(options.Password ?? throw new ArgumentException("Missing password", nameof(options))), iv));
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
                IBlockCipher cipher = CreateCipher(forEncryption: false, options);
                cipher.Init(forEncryption: false, new ParametersWithIV(new KeyParameter(options.Password ?? throw new ArgumentException("Missing password", nameof(options))), iv));
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
                IBlockCipher cipher = CreateCipher(forEncryption: false, options);
                cipher.Init(forEncryption: false, new ParametersWithIV(new KeyParameter(options.Password ?? throw new ArgumentException("Missing password", nameof(options))), iv));
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
        /// <returns>Block cipher</returns>
        protected abstract IBlockCipher CreateCipher(bool forEncryption, CryptoOptions options);
    }
}
