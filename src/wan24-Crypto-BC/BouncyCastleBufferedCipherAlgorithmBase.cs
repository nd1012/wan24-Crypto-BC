using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle buffered block cipher
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract record class BouncyCastleBufferedCipherAlgorithmBase<T> : BouncyCastleCipherAlgorithmBase<T> where T : BouncyCastleBufferedCipherAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Agorithm value</param>
        protected BouncyCastleBufferedCipherAlgorithmBase(string name, int value) : base(name, value) { }

        /// <inheritdoc/>
        protected sealed override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                IBufferedCipher cipher = CreateCipher(forEncryption: true, options);
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
                IBufferedCipher cipher = CreateCipher(forEncryption: true, options);
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
                IBufferedCipher cipher = CreateCipher(forEncryption: false, options);
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
                IBufferedCipher cipher = CreateCipher(forEncryption: false, options);
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
        /// <returns>Block cipher</returns>
        protected abstract IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options);
    }
}
