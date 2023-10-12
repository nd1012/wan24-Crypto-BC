using Org.BouncyCastle.Crypto.Prng;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle RNG wrapper for <c>wan24-Crypto</c>
    /// </summary>
    public sealed class RngWrapper : IRandomGenerator//TODO Extend SeedableRngBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rng">RNG</param>
        public RngWrapper(IRandomGenerator rng) => RNG = rng;

        /// <summary>
        /// Wrapped RNG
        /// </summary>
        public IRandomGenerator RNG { get; }

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RNG.NextBytes(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RNG.NextBytes(bytes, start, len);

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes)  => RNG.NextBytes(bytes);
    }
}
