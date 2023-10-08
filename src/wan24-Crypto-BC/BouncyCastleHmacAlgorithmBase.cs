using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a Bouncy Castle MAC algorithm
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract record class BouncyCastleHmacAlgorithmBase<T> : MacAlgorithmBase where T : BouncyCastleHmacAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleHmacAlgorithmBase() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected BouncyCastleHmacAlgorithmBase(string name, int value) : base(name, value) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static T Instance { get; }

        /// <summary>
        /// Register the algorithm to the <see cref="CryptoConfig"/>
        /// </summary>
        public static void Register() => CryptoConfig.AddAlgorithm(typeof(T), Instance.Name);
    }
}
