using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle cipher
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract record class BouncyCastleCipherAlgorithmBase<T> : EncryptionAlgorithmBase where T : BouncyCastleCipherAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleCipherAlgorithmBase() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Agorithm value</param>
        protected BouncyCastleCipherAlgorithmBase(string name, int value) : base(name, value) { }

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

        /// <summary>
        /// Create cipher parameters
        /// </summary>
        /// <param name="iv">IV bytes</param>
        /// <param name="options">Options</param>
        /// <returns>Parameters</returns>
        protected virtual ICipherParameters CreateParameters(byte[] iv, CryptoOptions options) => CreateIvParameters(iv, options);

        /// <summary>
        /// Create cipher parameters
        /// </summary>
        /// <param name="iv">IV bytes</param>
        /// <param name="options">Options</param>
        /// <returns>Parameters</returns>
        protected virtual ParametersWithIV CreateIvParameters(byte[] iv, CryptoOptions options)
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
        /// Create cipher parameters
        /// </summary>
        /// <param name="iv">IV bytes</param>
        /// <param name="options">Options</param>
        /// <param name="hashAlgo">Hash algorithm</param>
        /// <returns>Parameters</returns>
        protected virtual KeyParameter CreateKeyParameters(byte[] iv, CryptoOptions options, HashAlgorithmBase hashAlgo)
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
                using HashStreams hash = hashAlgo.GetHashStream(Stream.Null, options: options);
                hash.Stream.Write(iv);
                hash.Stream.Write(pwd);
                hash.FinalizeHash();
                return new KeyParameter(hash.Transform.Hash);
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
