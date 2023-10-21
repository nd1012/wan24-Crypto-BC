using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Random number generator for Bouncy Castle, which adopts <see cref="RND"/>
    /// </summary>
    public sealed class BouncyCastleRandomGenerator : IBouncyCastleRng
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
        public void AddSeed(ReadOnlySpan<byte> seed) => RND.AddSeed(seed);

        /// <inheritdoc/>
        public Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default) => RND.AddSeedAsync(seed, cancellationToken);

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) => RND.AddSeed(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed) => RND.AddSeed(seed);

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed)
        {
            using RentedArrayRefStruct<byte> buffer = new(sizeof(long), clean: false)
            {
                Clear = true
            };
            seed.GetBytes(buffer.Span);
            RND.AddSeed(buffer.Span);
        }

        /// <inheritdoc/>
        public Span<byte> FillBytes(in Span<byte> buffer)
        {
            RND.FillBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await RND.FillBytesAsync(buffer).DynamicContext();
            return buffer;
        }

        /// <inheritdoc/>
        public byte[] GetBytes(in int count) => RND.GetBytes(count);

        /// <inheritdoc/>
        public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default) => RND.GetBytesAsync(count);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => RND.FillBytes(bytes);

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => RND.FillBytes(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes) => RND.FillBytes(bytes);
    }
}
