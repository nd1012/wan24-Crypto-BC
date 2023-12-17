using Org.BouncyCastle.Crypto.Prng;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle RNG wrapper for <c>wan24-Crypto</c>
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">RNG</param>
    public sealed class BouncyCastleRngWrapper(in IRandomGenerator rng) : IBouncyCastleRng
    {
        /// <summary>
        /// Wrapped RNG
        /// </summary>
        public IRandomGenerator RNG { get; } = rng;

        /// <inheritdoc/>
        public void AddSeed(ReadOnlySpan<byte> seed) => AddSeedMaterial(seed);

        /// <inheritdoc/>
        public Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            AddSeedMaterial(seed.Span);
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public Span<byte> FillBytes(in Span<byte> buffer)
        {
            NextBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NextBytes(buffer.Span);
            return Task.FromResult(buffer);
        }

        /// <inheritdoc/>
        public byte[] GetBytes(in int count)
        {
            if (count < 1) return [];
            byte[] res = new byte[count];
            NextBytes(res);
            return res;
        }

        /// <inheritdoc/>
        public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            if (count < 1) return Task.FromResult(Array.Empty<byte>());
            byte[] res = new byte[count];
            NextBytes(res);
            return Task.FromResult(res);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RNG.NextBytes(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RNG.NextBytes(bytes, start, len);

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes)  => RNG.NextBytes(bytes);
    }
}
