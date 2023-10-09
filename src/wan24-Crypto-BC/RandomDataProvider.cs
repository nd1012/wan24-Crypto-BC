using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

//TODO Provide added seed

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Random data provider
    /// </summary>
    public class RandomDataProvider : RandomDataGenerator, IRandomGenerator
    {
        /// <summary>
        /// Random number generator
        /// </summary>
        protected readonly VmpcRandomGenerator RNG = new();
        /// <summary>
        /// RNG synchronization
        /// </summary>
        protected readonly SemaphoreSync RngSync = new();
        /// <summary>
        /// Seed provider
        /// </summary>
        protected readonly RandomDataProvider? SeedProvider;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="rdp">Random data provider to attach to (will be used for seeding, if available - otherwise fallback to <see cref="RND"/>)</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        public RandomDataProvider(in int capacity, in RandomDataProvider? rdp = null, in int? seed = null, in int? workerBufferSize = null) : this(rdp, capacity, workerBufferSize)
        {
            if (seed.HasValue && seed.Value < 1) throw new ArgumentOutOfRangeException(nameof(seed));
            InitialSeed(seed ?? Settings.BufferSize);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="rdp">Random data provider to attach to (will be used for seeding, if available - otherwise fallback to <see cref="RND"/>)</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        protected RandomDataProvider(in RandomDataProvider? rdp, in int capacity, in int? workerBufferSize) : base(capacity)
        {
            if (workerBufferSize.HasValue && workerBufferSize.Value < 1) throw new ArgumentOutOfRangeException(nameof(workerBufferSize));
            WorkerBufferSize = workerBufferSize ?? Settings.BufferSize;
            UseFallback = false;
            UseDevUrandom = false;
            SeedProvider = rdp;
            if (rdp is not null)
            {
                rdp.OnSeed += HandleSeed;
                rdp.OnDisposing += HandleSeedProviderDisposing;
            }
        }

        /// <summary>
        /// Worker buffer size in bytes
        /// </summary>
        public int WorkerBufferSize { get; }

        /// <summary>
        /// Create a fork instance, which attaches to this instances provided seeds
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <returns>Fork (service is not started yet; don't forget to dispose!)</returns>
        public virtual RandomDataProvider CreateFork(in int? capacity = null, in int? seed = null, in int? workerBufferSize = null)
        {
            EnsureUndisposed();
            return new(capacity ?? RandomData.BufferSize, this, seed, workerBufferSize ?? WorkerBufferSize);
        }

        /// <summary>
        /// Create a fork instance, which attaches to this instances provided seeds
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Fork (service is not started yet; don't forget to dispose!)</returns>
        public virtual Task<RandomDataProvider> CreateForkAsync(int? capacity = null, int? seed = null, in int? workerBufferSize = null, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            return CreateAsync(capacity ?? RandomData.BufferSize, this, seed, workerBufferSize ?? WorkerBufferSize, cancellationToken);
        }

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(byte[] seed)
        {
            throw new NotImplementedException();//TODO
        }

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(ReadOnlySpan<byte> seed)
        {
            throw new NotImplementedException();//TODO
        }

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(long seed)
        {
            throw new NotImplementedException();//TODO
        }

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(byte[] bytes) => Fill(bytes);

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(byte[] bytes, int start, int len) => Fill(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(Span<byte> bytes) => Fill(bytes);

        /// <summary>
        /// Handle seed
        /// </summary>
        /// <param name="rnp">Random number provider</param>
        /// <param name="e">Arguments</param>
        protected virtual void HandleSeed(RandomDataProvider rnp, SeedEventArgs e) => RngSync.ExecuteAsync(() =>
        {
            if (!EnsureUndisposed(throwException: false)) return Task.CompletedTask;
            RNG.AddSeedMaterial(e.Seed.Span);
            return Task.CompletedTask;
        });

        /// <summary>
        /// Hande a disposing seed provider
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">Arguments</param>
        protected virtual void HandleSeedProviderDisposing(IDisposableObject sender, EventArgs e) => Dispose();

        /// <summary>
        /// Perform initial seeding
        /// </summary>
        /// <param name="len">Initial seed length in bytes</param>
        protected virtual void InitialSeed(in int len)
        {
            using RentedArrayRefStruct<byte> buffer = new(len);
            if (SeedProvider is null)
            {
                RND.FillBytes(buffer.Span);
            }
            else
            {
                SeedProvider.FillBytes(buffer.Span);
            }
            RNG.AddSeedMaterial(buffer.Span);
        }

        /// <summary>
        /// Perform initial seeding
        /// </summary>
        /// <param name="len">Initial seed length in bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task InitialSeedAsync(int len, CancellationToken cancellationToken = default)
        {
            using RentedArrayStructSimple<byte> buffer = new(len);
            if (SeedProvider is null)
            {
                await RND.FillBytesAsync(buffer.Memory).DynamicContext();
            }
            else
            {
                await SeedProvider.FillBytesAsync(buffer.Memory, cancellationToken).DynamicContext();
            }
            RNG.AddSeedMaterial(buffer.Span);
        }

        /// <inheritdoc/>
        protected override async Task WorkerAsync()
        {
            using RentedArrayStructSimple<byte> buffer1 = new(WorkerBufferSize, clean: false);
            using RentedArrayStructSimple<byte> buffer2 = new(WorkerBufferSize, clean: false);
            for (; !CancelToken.IsCancellationRequested;)
            {
                await RngSync.ExecuteAsync(() =>
                {
                    RNG.NextBytes(buffer1.Span);
                    return Task.CompletedTask;
                }, CancelToken).DynamicContext();
                CancelToken.ThrowIfCancellationRequested();
                await RND.DefaultRngAsync(buffer2.Memory).DynamicContext();
                CancelToken.ThrowIfCancellationRequested();
                buffer1.Span.Xor(buffer2.Span);
                await RandomData.WriteAsync(buffer1.Memory, CancelToken).DynamicContext();
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (SeedProvider is not null)
            {
                SeedProvider!.OnDisposing -= HandleSeedProviderDisposing;
                SeedProvider.OnSeed -= HandleSeed;
            }
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (SeedProvider is not null)
            {
                SeedProvider!.OnDisposing -= HandleSeedProviderDisposing;
                SeedProvider.OnSeed -= HandleSeed;
            }
        }

        /// <summary>
        /// Delegate for a seed handler
        /// </summary>
        /// <param name="rnp">Random number provider</param>
        /// <param name="e">Arguments</param>
        public delegate void Seed_Delegate(RandomDataProvider rnp, SeedEventArgs e);
        /// <summary>
        /// Raised when seeded
        /// </summary>
        public event Seed_Delegate? OnSeed;
        /// <summary>
        /// Raise the <see cref="OnSeed"/> event
        /// </summary>
        /// <param name="seed">Seed</param>
        protected virtual void RaiseOnSeed(byte[] seed) => OnSeed?.Invoke(this, new(seed));

        /// <summary>
        /// Create an instance
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="rdp">Random data provider to attach to (will be used for seeding, if available - otherwise fallback to <see cref="RND"/>)</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Instance (service is not started yet; don't forget to dispose!)</returns>
        public static async Task<RandomDataProvider> CreateAsync(
            int capacity,
            RandomDataProvider? rdp = null,
            int? seed = null,
            int? workerBufferSize = null,
            CancellationToken cancellationToken = default
            )
        {
            if (seed.HasValue && seed.Value < 1) throw new ArgumentOutOfRangeException(nameof(seed));
            RandomDataProvider res = new(rdp, capacity, workerBufferSize);
            try
            {
                await res.InitialSeedAsync(seed ?? Settings.BufferSize, cancellationToken).DynamicContext();
                return res;
            }
            catch
            {
                await res.DisposeAsync().DynamicContext();
                throw;
            }
        }

        /// <summary>
        /// <see cref="OnSeed"/> event arguments
        /// </summary>
        public class SeedEventArgs : EventArgs
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="seed">Seed</param>
            public SeedEventArgs(ReadOnlyMemory<byte> seed) : base() => Seed = seed;

            /// <summary>
            /// Seed
            /// </summary>
            public ReadOnlyMemory<byte> Seed { get; }
        }
    }
}
