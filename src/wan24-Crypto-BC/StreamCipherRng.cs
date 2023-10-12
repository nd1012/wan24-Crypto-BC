using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Stream cipher CSRNG
    /// </summary>
    public class StreamCipherRng : DisposableBase, IRandomGenerator//TODO What about ISeedableRng?
    {
        /// <summary>
        /// RNG synchronization
        /// </summary>
        protected readonly SemaphoreSync RngSync = new();
        /// <summary>
        /// Buffer
        /// </summary>
        protected readonly BlockingBufferStream Buffer = null!;
        /// <summary>
        /// Cipher stream
        /// </summary>
        protected readonly EncryptionStreams Encryption = null!;
        /// <summary>
        /// Internal RNG to use
        /// </summary>
        protected readonly IRandomGenerator RNG = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Encryption algorithm to use</param>
        /// <param name="rng">Internal RNG to use (will be disposed, if possible!)</param>
        /// <param name="bufferSize">Buffer size in bytes (min. the IV byte length of the underlaying cipher)</param>
        /// <param name="seedLength">Seed the given RNG with N byte from <see cref="RND"/> (skipped, if <see langword="null"/> or <c>&lt;1</c>)</param>
        public StreamCipherRng(
            in EncryptionAlgorithmBase algorithm, 
            IRandomGenerator? rng = null, //TODO Support ISeedableRng
            in int? bufferSize = null, 
            in int? seedLength = 256
            )
            : base(asyncDisposing: false)
        {
            Algorithm = algorithm;
            try
            {
                if (algorithm.BlockSize != 1) throw new ArgumentException("Stream cipher required", nameof(algorithm));
                if (bufferSize.HasValue && bufferSize.Value < Algorithm.IvSize)
                    throw new ArgumentOutOfRangeException(nameof(bufferSize), $"Min. buffer size for {algorithm.DisplayName} is {algorithm.IvSize} byte");
                rng ??= new VmpcRandomGenerator();
                // Create a buffer for chunking random sequences
                Buffer = new(bufferSize ?? Settings.BufferSize, clear: true);
                // Seed the RNG
                if (seedLength > 0)
                    using (RentedArray<byte> seed = new(len: seedLength.Value, clean: false)
                    {
                        Clear = true
                    })
                    {
                        RND.FillBytes(seed.Span);
                        rng.AddSeedMaterial(seed.Span);
                    }
                // Create a random key
                using SecureByteArrayRefStruct key = new(algorithm.KeySize);
                rng.NextBytes(key.Span);
                // Create encryption options
                CryptoOptions options = new CryptoOptions()
                {
                    Password = key.Array
                }
                    .IncludeNothing()
                    .WithoutMac()
                    .WithoutKdf()
                    .WithoutCompression();
                options.FlagsIncluded = false;
                // Create the cipher stream
                Encryption = Algorithm.GetEncryptionStream(Stream.Null, Buffer, macStream: null, options);
                // Remove the written IV bytes from the buffer
                if (algorithm.IvSize > 0)
                {
                    if (Buffer.Available != algorithm.IvSize)
                        throw CryptographicException.From(
                            $"{algorithm.DisplayName} stream initialization failed: {Buffer.Available} IV byte buffered ({algorithm.IvSize} byte expected)",
                            new InvalidProgramException()
                            );
                    using RentedArray<byte> buffer = new(algorithm.IvSize, clean: false)
                    {
                        Clear = true
                    };
                    int red = Buffer.TryRead(buffer.Span);
                    if (red != algorithm.IvSize)
                        throw CryptographicException.From(
                            $"{algorithm.DisplayName} stream initialization failed: {Buffer.Available} IV byte buffered, but only {red} byte red",
                            new InvalidProgramException()
                            );
                }
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

        /// <summary>
        /// Encryption algorithm to use
        /// </summary>
        public EncryptionAlgorithmBase Algorithm { get; }

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(byte[] seed)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = RngSync;
            RNG.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            using SemaphoreSyncContext ssc = RngSync;
            RNG.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public virtual void AddSeedMaterial(long seed)
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
        public virtual void NextBytes(Span<byte> bytes)
        {
            EnsureUndisposed();
            if (bytes.Length == 0) return;
            using SemaphoreSyncContext ssc = RngSync;
            for (int write; bytes.Length != 0; bytes = bytes[write..])
            {
                write = Math.Min(bytes.Length, Buffer.BufferSize);
                RNG.NextBytes(bytes[..write]);
                Encryption.CryptoStream.Write(bytes[..write]);
                Encryption.CryptoStream.Flush();
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
            using EncryptionStreams chaCha = Encryption;
            RNG?.TryDispose();
        }
    }
}
