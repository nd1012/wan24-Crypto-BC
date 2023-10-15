using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle disposable RNG wrapper for <c>wan24-Crypto</c>
    /// </summary>
    public sealed class DisposableRngWrapper : DisposableSeedableRngBase, IRandomGenerator
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rng">RNG</param>
        public DisposableRngWrapper(IRandomGenerator rng) : base() => RNG = rng;

        /// <summary>
        /// Wrapped RNG
        /// </summary>
        public IRandomGenerator RNG { get; }

        /// <inheritdoc/>
        public override void AddSeed(ReadOnlySpan<byte> seed) => AddSeedMaterial(seed);

        /// <inheritdoc/>
        public override Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
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
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            NextBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public override Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NextBytes(buffer.Span);
            return Task.FromResult(buffer);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RNG.NextBytes(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RNG.NextBytes(bytes, start, len);

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes) => RNG.NextBytes(bytes);

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => RNG.TryDispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await RNG.TryDisposeAsync().DynamicContext();
    }
}
