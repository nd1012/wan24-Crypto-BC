using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle AEAD stream cipher
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract record class BouncyCastleAeadCipherAlgorithmBase<T> : BouncyCastleCipherAlgorithmBase<T> where T : BouncyCastleAeadCipherAlgorithmBase<T>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected BouncyCastleAeadCipherAlgorithmBase(string name, int value) : base(name, value) { }

        /// <summary>
        /// Create the cipher engine
        /// </summary>
        /// <param name="forEncryption">For encryption?</param>
        /// <param name="options">Options</param>
        /// <returns>Stream cipher</returns>
        protected abstract IBufferedCipher CreateCipher(bool forEncryption, CryptoOptions options);

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

        /// <inheritdoc/>
        protected sealed override ICipherParameters CreateParameters(byte[] iv, CryptoOptions options)
        {
            byte[] pwd = options.Password?.CloneArray() ?? throw new ArgumentException("Missing password", nameof(options));
            try
            {
                if (!IsKeyLengthValid(pwd.Length))
                {
                    byte[] temp = EnsureValidKeyLength(pwd);
                    pwd.Clear();
                    pwd = temp;
                }
                return new AeadParameters(new KeyParameter(pwd), macSize: 128, iv);
            }
            finally
            {
                pwd.Clear();
            }
        }
    }
}
