using Org.BouncyCastle.Crypto.Prng;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Random number generator for Bouncy Castle, which adopts <see cref="RND"/>
    /// </summary>
    public sealed class BouncyCastleRandomGenerator : IRandomGenerator
    {
        /// <summary>
        /// Instance
        /// </summary>
        private static readonly BouncyCastleRandomGenerator _Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        public BouncyCastleRandomGenerator() { }

        /// <summary>
        /// Instance factory
        /// </summary>
        public static Func<IRandomGenerator> Instance { get; set; } = () => _Instance;

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed) { }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RND.FillBytes(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RND.FillBytes(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes) => RND.FillBytes(bytes);
    }
}
