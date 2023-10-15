using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Random data provider
    /// </summary>
    public class RandomDataProvider : RandomDataGenerator, IBouncyCastleRng // Note for myself: Do not try to move this to wan24-Crypto - it won't work...
    {
        /// <summary>
        /// Random number generator
        /// </summary>
        protected readonly ISeedableRng RNG;
        /// <summary>
        /// RNG synchronization
        /// </summary>
        protected readonly SemaphoreSync RngSync = new();
        /// <summary>
        /// Seed provider
        /// </summary>
        protected readonly RandomDataProvider? SeedProvider;
        /// <summary>
        /// Raised when seeded
        /// </summary>
        protected readonly AsyncEvent<RandomDataProvider, SeedEventArgs> _OnSeedAsync;
        /// <summary>
        /// Did initialize?
        /// </summary>
        protected bool DidInit = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="rdp">Random data provider to attach to (will be used for seeding, if available - otherwise fallback to <see cref="RND"/>)</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <param name="rng">RNG to use</param>
        public RandomDataProvider(
            in int capacity, 
            in RandomDataProvider? rdp = null, 
            in int? seed = null, 
            in int? workerBufferSize = null,
            in ISeedableRng? rng = null
            )
            : this(rdp, capacity, workerBufferSize, rng)
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
        /// <param name="rng">RNG to use (will be disposed, if possible)</param>
        protected RandomDataProvider(in RandomDataProvider? rdp, in int capacity, in int? workerBufferSize, in ISeedableRng? rng = null) : base(capacity)
        {
            if (workerBufferSize.HasValue && workerBufferSize.Value < 1) throw new ArgumentOutOfRangeException(nameof(workerBufferSize));
            RNG = rng ?? new ChaCha20Rng(new BouncyCastleRngWrapper(new VmpcRandomGenerator()), byte.MaxValue);
            _OnSeedAsync = new(this);
            WorkerBufferSize = workerBufferSize ?? Settings.BufferSize;
            UseFallback = false;
            UseDevUrandom = false;
            SeedProvider = rdp;
            if (rdp is not null)
            {
                rdp.OnSeedAsync += HandleSeedAsync;
                rdp.OnDisposing += HandleSeedProviderDisposing;
            }
        }

        /// <summary>
        /// Raised when seeded
        /// </summary>
        public AsyncEvent<RandomDataProvider, SeedEventArgs> OnSeedAsync
        {
            get => _OnSeedAsync;
            set { }
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
        /// <param name="rng">RNG to use (the RNG of this instance won't be used in the fork!)</param>
        /// <returns>Fork (service is not started yet; don't forget to dispose!)</returns>
        public virtual RandomDataProvider CreateFork(in int? capacity = null, in int? seed = null, in int? workerBufferSize = null, in ISeedableRng? rng = null)
        {
            EnsureUndisposed();
            return new(capacity ?? RandomData.BufferSize, this, seed, workerBufferSize ?? WorkerBufferSize, rng);
        }

        /// <summary>
        /// Create a fork instance, which attaches to this instances provided seeds
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <param name="rng">RNG to use (the RNG of this instance won't be used in the fork!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Fork (service is not started yet; don't forget to dispose!)</returns>
        public virtual Task<RandomDataProvider> CreateForkAsync(
            int? capacity = null, 
            int? seed = null, 
            int? workerBufferSize = null,
            ISeedableRng? rng = null,
            CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            return CreateAsync(capacity ?? RandomData.BufferSize, this, seed, workerBufferSize ?? WorkerBufferSize, rng, cancellationToken);
        }

        /// <inheritdoc/>
        public override void AddSeed(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            if (seed.Length == 0) return;
            RNG.AddSeed(seed);
            using RentedArrayStructSimple<byte> buffer = new(seed.Length);
            seed.CopyTo(buffer.Span);
            RaiseOnSeed(buffer.Memory);
        }

        /// <inheritdoc/>
        public override async Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            if (seed.Length == 0) return;
            await RNG.AddSeedAsync(seed, cancellationToken).DynamicContext();
            await RaiseOnSeedAsync(seed,cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(byte[] seed) => AddSeed(seed);

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(ReadOnlySpan<byte> seed) => AddSeed(seed);

        /// <inheritdoc/>
        void IRandomGenerator.AddSeedMaterial(long seed)
        {
            using RentedArrayRefStruct<byte> buffer = new(sizeof(long));
            seed.GetBytes(buffer.Span);
            AddSeed(buffer.Span);
        }

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(byte[] bytes) => Fill(bytes);

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(byte[] bytes, int start, int len) => Fill(bytes.AsSpan(start, len));

        /// <inheritdoc/>
        void IRandomGenerator.NextBytes(Span<byte> bytes) => Fill(bytes);

        /// <summary>
        /// Handle seed from the parent
        /// </summary>
        /// <param name="rnp">Random number provider</param>
        /// <param name="e">Arguments</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task HandleSeedAsync(RandomDataProvider rnp, SeedEventArgs e, CancellationToken cancellationToken)
        {
            if (!DidInit) return;
            try
            {
                await AddSeedAsync(e.Seed, cancellationToken).DynamicContext();
            }
            catch (Exception ex)
            {
                ErrorHandling.Handle(new(
                    $"Failed to seed a {GetType()} instance (\"{Name}\") from seed provider {rnp.GetType()} (\"{rnp.Name}\")",
                    ex,
                    Constants.CRYPTO_ERROR_SOURCE
                    ));
            }
        }

        /// <summary>
        /// Handle a disposing seed provider
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
            RNG.AddSeed(buffer.Span);
            DidInit = true;
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
            await RNG.AddSeedAsync(buffer.Memory, cancellationToken).DynamicContext();
            DidInit = true;
        }

        /// <inheritdoc/>
        protected override async Task WorkerAsync()
        {
            bool isDefaultRng = RND.Generator == this;
            using RentedArrayStructSimple<byte> buffer1 = new(WorkerBufferSize, clean: false)
            {
                Clear = true
            };
            if (isDefaultRng)// Avoids an endless recursion when using this instance as RND.Generator
            {
                for (; !CancelToken.IsCancellationRequested;)
                {
                    await RngSync.ExecuteAsync(async () =>
                    {
                        await RNG.FillBytesAsync(buffer1.Memory, CancelToken).DynamicContext();
                        return Task.CompletedTask;
                    }, CancelToken).DynamicContext();
                    CancelToken.ThrowIfCancellationRequested();
                    await RandomData.WriteAsync(buffer1.Memory, CancelToken).DynamicContext();
                }
            }
            else
            {
                using RentedArrayStructSimple<byte> buffer2 = new(WorkerBufferSize, clean: false)
                {
                    Clear = true
                };
                for (; !CancelToken.IsCancellationRequested;)
                {
                    await RngSync.ExecuteAsync(async () =>
                    {
                        await RNG.FillBytesAsync(buffer1.Memory, CancelToken).DynamicContext();
                        return Task.CompletedTask;
                    }, CancelToken).DynamicContext();
                    CancelToken.ThrowIfCancellationRequested();
                    await RND.DefaultRngAsync(buffer2.Memory).DynamicContext();
                    CancelToken.ThrowIfCancellationRequested();
                    buffer1.Span.Xor(buffer2.Span);
                    await RandomData.WriteAsync(buffer1.Memory, CancelToken).DynamicContext();
                }
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (SeedProvider is not null)
            {
                SeedProvider!.OnDisposing -= HandleSeedProviderDisposing;
                SeedProvider.OnSeedAsync -= HandleSeedAsync;
            }
            RngSync.Dispose();
            RNG.TryDispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            if (SeedProvider is not null)
            {
                SeedProvider!.OnDisposing -= HandleSeedProviderDisposing;
                SeedProvider.OnSeedAsync -= HandleSeedAsync;
            }
            await RngSync.DisposeAsync().DynamicContext();
            await RNG.TryDisposeAsync().DynamicContext();
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
        protected virtual void RaiseOnSeed(in ReadOnlyMemory<byte> seed)
        {
            SeedEventArgs e = new(seed);
            Task task = OnSeedAsync.Abstract.RaiseEventAsync(this, e, cancellationToken: CancelToken);
            OnSeed?.Invoke(this, e);
            task.Wait();
        }
        /// <summary>
        /// Raise the <see cref="OnSeed"/> event
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task RaiseOnSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken)
        {
            SeedEventArgs e = new(seed);
            Task task = OnSeedAsync.Abstract.RaiseEventAsync(this, e, cancellationToken: CancelToken);
            OnSeed?.Invoke(this, e);
            await task.DynamicContext();
        }

        /// <summary>
        /// Create an instance
        /// </summary>
        /// <param name="capacity">Buffer capacity in bytes</param>
        /// <param name="rdp">Random data provider to attach to (will be used for seeding, if available - otherwise fallback to <see cref="RND"/>)</param>
        /// <param name="seed">Initial seed length in bytes</param>
        /// <param name="workerBufferSize">Worker buffer size in bytes</param>
        /// <param name="rng">RNG to use</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Instance (service is not started yet; don't forget to dispose!)</returns>
        public static async Task<RandomDataProvider> CreateAsync(
            int capacity,
            RandomDataProvider? rdp = null,
            int? seed = null,
            int? workerBufferSize = null,
            ISeedableRng? rng = null,
            CancellationToken cancellationToken = default
            )
        {
            if (seed.HasValue && seed.Value < 1) throw new ArgumentOutOfRangeException(nameof(seed));
            if (workerBufferSize.HasValue && workerBufferSize.Value < 1) throw new ArgumentOutOfRangeException(nameof(workerBufferSize));
            RandomDataProvider res = new(rdp, capacity, workerBufferSize, rng);
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
            public SeedEventArgs() : base() { }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="seed">Seed</param>
            public SeedEventArgs(in ReadOnlyMemory<byte> seed) : this() => Seed = seed;

            /// <summary>
            /// Seed
            /// </summary>
            public ReadOnlyMemory<byte> Seed { get; } = null!;
        }
    }
}
