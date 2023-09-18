namespace wan24.Crypto.BC
{
    /// <summary>
    /// Base class for a BouncyCastle hash algorithm
    /// </summary>
    /// <typeparam name="T">Final type</typeparam>
    public abstract class BouncyCastleHashAlgorithmBase<T> : HashAlgorithmBase where T : BouncyCastleHashAlgorithmBase<T>, new()
    {
        /// <summary>
        /// Static constructor
        /// </summary>
        static BouncyCastleHashAlgorithmBase() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected BouncyCastleHashAlgorithmBase(string name, int value) : base(name, value) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static T Instance { get; }
    }
}
