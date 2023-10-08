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
    public abstract record class BouncyCastleBlockCipherAlgorithmBase<T> : EncryptionAlgorithmBase where T : BouncyCastleBlockCipherAlgorithmBase<T>, new()
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
        protected override byte[] GetValidLengthKey(byte[] key, int len)
            => key.Length == len ? key.CloneArray() : len switch
            {
                HashMd5Algorithm.HASH_LENGTH => HashMd5Algorithm.Instance.Hash(key),
                HashSha1Algorithm.HASH_LENGTH => HashSha1Algorithm.Instance.Hash(key),
                HashSha3_256Algorithm.HASH_LENGTH => HashSha3_256Algorithm.Instance.Hash(key),
                HashSha3_384Algorithm.HASH_LENGTH => HashSha3_384Algorithm.Instance.Hash(key),
                HashSha3_512Algorithm.HASH_LENGTH => HashSha3_512Algorithm.Instance.Hash(key),
                _ => throw CryptographicException.From($"Can't process for desired key length {len} bytes", new NotSupportedException())
            };

        /// <inheritdoc/>
        protected sealed override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                IBlockCipher cipher = CreateCipher(forEncryption: true, options);
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
                IBlockCipher cipher = CreateCipher(forEncryption: true, options);
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
                IBlockCipher cipher = CreateCipher(forEncryption: false, options);
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
                IBlockCipher cipher = CreateCipher(forEncryption: false, options);
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
        protected abstract IBlockCipher CreateCipher(bool forEncryption, CryptoOptions options);

        /// <summary>
        /// Create cipher parameters
        /// </summary>
        /// <param name="iv">IV bytes</param>
        /// <param name="options">Options</param>
        /// <returns>Parameters</returns>
        protected virtual ICipherParameters CreateParameters(byte[] iv, CryptoOptions options)
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
                return new ParametersWithIV(new KeyParameter(pwd), iv);
            }
            finally
            {
                pwd.Clear();
            }
        }

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(T), Instance.Name);
    }
}
