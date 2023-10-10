using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// ChaCha20 CSRNG
    /// </summary>
    public sealed class ChaCha20Rng : DisposableBase, IRandomGenerator
    {
        /// <summary>
        /// RNG synchronization
        /// </summary>
        private readonly SemaphoreSync RngSync = new();
        /// <summary>
        /// Buffer
        /// </summary>
        private readonly BlockingBufferStream Buffer = null!;
        /// <summary>
        /// ChaCha20 stream
        /// </summary>
        private readonly EncryptionStreams ChaCha = null!;
        /// <summary>
        /// Internal RNG to use
        /// </summary>
        private readonly IRandomGenerator RNG = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rng">Internal RNG to use (will be disposed, if possible!)</param>
        /// <param name="bufferSize">Buffer size in bytes (min. <see cref="EncryptionChaCha20Algorithm.IV_SIZE"/>)</param>
        /// <param name="seedLength">Seed the given RNG with N byte from <see cref="RND"/> (skipped, if <see langword="null"/> or <c>&lt;1</c>)</param>
        public ChaCha20Rng(in IRandomGenerator rng, in int? bufferSize = null, in int? seedLength = 256) : base(asyncDisposing: false)
        {
            try
            {
                if (bufferSize.HasValue && bufferSize.Value < EncryptionChaCha20Algorithm.IV_SIZE) throw new ArgumentOutOfRangeException(nameof(bufferSize));
                // Create a buffer for chunking random sequences
                Buffer = new(bufferSize ?? Settings.BufferSize, clear: true);
                // Seed the given RNG
                if (seedLength > 0)
                    using (RentedArray<byte> seed = new(len: seedLength.Value, clean: false)
                    {
                        Clear = true
                    })
                    {
                        RND.FillBytes(seed.Span);
                        rng.AddSeedMaterial(seed.Span);
                    }
                // Create a random key for ChaCha20
                using SecureByteArrayRefStruct key = new(EncryptionChaCha20Algorithm.KEY_SIZE);
                rng.NextBytes(key.Span);
                // Create ChaCha20 encryption options
                CryptoOptions options = new CryptoOptions()
                {
                    Password = key.Array
                }
                    .IncludeNothing()
                    .WithoutMac()
                    .WithoutKdf()
                    .WithoutCompression();
                // Create the ChaCha20 engine
                ChaCha = EncryptionChaCha20Algorithm.Instance.GetEncryptionStream(
                    Stream.Null,
                    Buffer,
                    macStream: null,
                    options
                    );
                // Remove the written IV bytes from the buffer
                if (Buffer.Available != EncryptionChaCha20Algorithm.IV_SIZE)
                    throw CryptographicException.From(
                        $"ChaCha20 stream initialization failed: {Buffer.Available} IV byte buffered ({EncryptionChaCha20Algorithm.IV_SIZE} byte expected)", 
                        new InvalidProgramException()
                        );
                using RentedArray<byte> buffer = new(EncryptionChaCha20Algorithm.IV_SIZE, clean: false)
                {
                    Clear = true
                };
                Buffer.TryRead(buffer.Span);
                // Store the internal RNG to use
                RNG = rng;
            }
            catch
            {
                Dispose();
                rng.TryDispose();
                throw;
            }
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = RngSync;
            RNG.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = RngSync;
            RNG.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = RngSync;
            RNG.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) => NextBytes(bytes.AsSpan());

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) => NextBytes(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes)
        {
            EnsureUndisposed();
            if (bytes.Length == 0) return;
            using SemaphoreSyncContext ssc = RngSync;
            for (int write; bytes.Length != 0; bytes = bytes[write..])
            {
                write = Math.Min(bytes.Length, Buffer.BufferSize);
                RNG.NextBytes(bytes[..write]);
                ChaCha.CryptoStream.Write(bytes[..write]);
                ChaCha.CryptoStream.Flush();
                if (Buffer.Read(bytes[..write]) != write)
                    throw CryptographicException.From("Failed to read all random data from the buffer", new InvalidProgramException());
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            using SemaphoreSync rngSync = RngSync;
            using SemaphoreSyncContext ssc = rngSync;
            using Stream buffer = Buffer;
            using EncryptionStreams chaCha = ChaCha;
            RNG?.TryDispose();
        }
    }
}
