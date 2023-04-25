using Org.BouncyCastle.Crypto.Prng;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Random number generator for Bouncy Castle, which adopts <see cref="RandomNumberGenerator"/>
    /// </summary>
    public sealed class RandomGenerator : IRandomGenerator
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public RandomGenerator() { }

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed) { }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RandomNumberGenerator.Fill(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RandomNumberGenerator.Fill(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes) => RandomNumberGenerator.Fill(bytes);
    }
}
