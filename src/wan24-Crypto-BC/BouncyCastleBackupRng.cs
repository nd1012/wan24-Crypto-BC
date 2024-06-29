using System.Collections.Frozen;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// RNG which uses backup RNGs on error (not seedable!)
    /// </summary>
    public class BouncyCastleBackupRng : IBouncyCastleRng
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rngs">RNGs</param>
        public BouncyCastleBackupRng(params IBouncyCastleRng[] rngs)
        {
            if (rngs.Length < 1) throw new ArgumentOutOfRangeException(nameof(rngs));
            RNGs = rngs.ToFrozenSet();
        }

        /// <summary>
        /// RNGs
        /// </summary>
        public FrozenSet<IBouncyCastleRng> RNGs { get; }

        /// <inheritdoc/>
        public void AddSeed(ReadOnlySpan<byte> seed) { }

        /// <inheritdoc/>
        public Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default) => Task.CompletedTask;

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) { }

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed) { }

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
            NextBytes(res.AsSpan());
            return res;
        }

        /// <inheritdoc/>
        public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
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
            List<Exception> exceptions = [];
            foreach (IBouncyCastleRng rng in RNGs)
                try
                {
                    rng.NextBytes(bytes);
                    return;
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            throw CryptographicException.From(new AggregateException("No RNG produced RND without an error", [.. exceptions]));
        }
    }
}
