using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Entropy monitoring RNG (uses <see cref="EntropyHelper.CheckEntropy(in ReadOnlySpan{byte}, EntropyHelper.Algorithms?, in bool)"/>; won't monitor seed)
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">Entropy monitored RNG (will be disposed)</param>
    public class DisposableBouncyCastleEntropyMonitor(in IBouncyCastleRng rng) : DisposableBase(), IBouncyCastleRng
    {
        /// <summary>
        /// Entropy monitored RNG (will be disposed)
        /// </summary>
        public IBouncyCastleRng RNG { get; } = rng;

        /// <summary>
        /// Entropy algorithms to use
        /// </summary>
        public EntropyHelper.Algorithms? Algorithms { get; init; }

        /// <summary>
        /// Max. number of retries to get RND with the required entropy (zero for no limit)
        /// </summary>
        public int MaxRetries { get; init; }

        /// <summary>
        /// Min. RND length required for monitoring
        /// </summary>
        public int MinRndlength { get; init; }

        /// <inheritdoc/>
        public virtual void AddSeed(ReadOnlySpan<byte> seed) => RNG.AddSeed(seed);

        /// <inheritdoc/>
        public virtual Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default) => RNG.AddSeedAsync(seed, cancellationToken);

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(byte[] seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(ReadOnlySpan<byte> seed) => RNG.AddSeedMaterial(seed);

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(long seed) => RNG.AddSeedMaterial(seed);

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
            EnsureUndisposed();
            if (count < 1) return [];
            byte[] res = new byte[count];
            NextBytes(res.AsSpan());
            return res;
        }

        /// <inheritdoc/>
        public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (count < 1) return Task.FromResult(Array.Empty<byte>());
            byte[] res = new byte[count];
            NextBytes(res.AsSpan());
            return Task.FromResult(res);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => NextBytes(bytes.AsSpan());

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => NextBytes(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes)
        {
            EnsureUndisposed();
            if (bytes.Length < 1) return;
            for (int i = 0, len = MaxRetries < 1 ? int.MaxValue : MaxRetries; i < len && EnsureUndisposed(); i++)
            {
                RNG.NextBytes(bytes);
                if (bytes.Length < MinRndlength || EntropyHelper.CheckEntropy(bytes, Algorithms)) return;
            }
            throw CryptographicException.From("Failed to get RND with the required entropy", new InvalidDataException());
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => RNG.TryDispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await RNG.TryDisposeAsync().DynamicContext();
    }
}
