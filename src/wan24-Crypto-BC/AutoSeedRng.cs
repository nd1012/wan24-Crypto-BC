using Org.BouncyCastle.Crypto.Prng;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Automatic seeding RNG
    /// </summary>
    public class AutoSeedRng : DisposableRngBase, IBouncyCastleRng
    {
        /// <summary>
        /// Seed background task
        /// </summary>
        protected readonly Task SeedTask;
        /// <summary>
        /// Seed event (raised when should add seed)
        /// </summary>
        protected readonly ResetEvent SeedEvent = new(initialState: true);
        /// <summary>
        /// Seed timeout cancellation
        /// </summary>
        protected readonly CancellationTokenSource SeedTimeoutCancellation = new();
        /// <summary>
        /// Seeding type
        /// </summary>
        protected AutoSeedRngTypes _Seeding;
        /// <summary>
        /// Seeding interval
        /// </summary>
        protected TimeSpan _SeedInterval;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="seedProvider">Seed provider (will be disposed, if <see cref="DisposeSeedProvider"/> is <see langword="true"/>)</param>
        /// <param name="seedLength">Seed length to get from <c>seedProvider</c>> and feed to <c>rng</c> in bytes</param>
        /// <param name="seedingType">Seeding type</param>
        /// <param name="seedInterval">Seeding interval (must be greater than <see cref="TimeSpan.Zero"/>; has only an effect if see <c>seedingType</c>> is 
        /// <see cref="AutoSeedRngTypes.Interval"/>; using 10 seconds as default)</param>
        /// <param name="rng">RNG to use (gets initial seed during construction unless <c>initialSeedLength</c> is lower than one; using <see cref="VmpcRandomGenerator"/> per 
        /// default; will be disposed, if <see cref="DisposeRng"/> is <see langword="true"/>)</param>
        /// <param name="initialSeedLength"><c>prng</c> initial seed lenght in bytes (<c>0</c> to skip initial seed; using <c>seedLength</c> as default)</param>
        /// <param name="taskScheduler">Task scheduler to use for the background seeding task</param>
        /// <param name="cancellationToken">Cancellation token to use for the background seeding task</param>
        public AutoSeedRng(
            in IRng seedProvider,
            in int seedLength = 256,
            in AutoSeedRngTypes seedingType = AutoSeedRngTypes.AfterRndConsumed,
            in TimeSpan seedInterval = default,
            in IBouncyCastleRng? rng = null,
            in int? initialSeedLength = null,
            in TaskScheduler? taskScheduler = null,
            in CancellationToken cancellationToken = default
            )
            : base()
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(seedLength, 1);
            SeedProvider = seedProvider;
            SeedLength = seedLength;
            DisposeSeedProvider = seedProvider.IsDisposable();
            _Seeding = seedingType;
            _SeedInterval = seedInterval == default ? TimeSpan.FromSeconds(10) : default;
            switch (seedingType)
            {
                case AutoSeedRngTypes.AfterRndConsumed:
                    SeedEvent.Reset(cancellationToken);
                    break;
                case AutoSeedRngTypes.Permanent:
                case AutoSeedRngTypes.Interval:
                    break;
                default:
                    throw new ArgumentException("Invalid seeding type", nameof(seedingType));
            }
            Rng = rng ?? new BouncyCastleRngWrapper(new VmpcRandomGenerator());
            DisposeRng = rng?.IsDisposable() ?? false;
            if (!initialSeedLength.HasValue || initialSeedLength > 0)
            {
                using RentedArrayRefStruct<byte> buffer = new(initialSeedLength ?? seedLength, clean: false);
                seedProvider.FillBytes(buffer.Span);
                Rng.AddSeed(buffer.Span);
                Rng.FillBytes(buffer.Span);
            }
            SeedTask = ((Func<Task>)SeedAsync).StartLongRunningTask(taskScheduler, cancellationToken);
        }

        /// <summary>
        /// Seed provider (will be disposed, if <see cref="DisposeSeedProvider"/> is <see langword="true"/>)
        /// </summary>
        public IRng SeedProvider { get; }

        /// <summary>
        /// Seed length to get from <see cref="SeedProvider"/> and feed to <see cref="Rng"/> in bytes
        /// </summary>
        public int SeedLength { get; }

        /// <summary>
        /// If to dispose the <see cref="SeedProvider"/> when disposing
        /// </summary>
        public bool DisposeSeedProvider { get; set; }

        /// <summary>
        /// RNG (used for seeding and as RNG; will be disposed, if <see cref="DisposeRng"/> is <see langword="true"/>)
        /// </summary>
        public IBouncyCastleRng Rng { get; }

        /// <summary>
        /// If to dispose the <see cref="Rng"/> when disposing
        /// </summary>
        public bool DisposeRng { get; set; }

        /// <summary>
        /// Seeding type
        /// </summary>
        public AutoSeedRngTypes SeedingType
        {
            get => IfUndisposed(_Seeding);
            set
            {
                EnsureUndisposed();
                if (value == _Seeding) return;
                switch (value)
                {
                    case AutoSeedRngTypes.AfterRndConsumed:
                        _Seeding = value;
                        SeedEvent.Reset();
                        break;
                    case AutoSeedRngTypes.Permanent:
                    case AutoSeedRngTypes.Interval:
                        _Seeding = value;
                        SeedEvent.Set();
                        break;
                    default:
                        throw new ArgumentException("Invalid seeding type", nameof(value));
                }
            }
        }

        /// <summary>
        /// Seed interval (must be greater than <see cref="TimeSpan.Zero"/>; has only an effect if see <see cref="SeedingType"/> is <see cref="AutoSeedRngTypes.Interval"/>)
        /// </summary>
        public TimeSpan SeedInterval
        {
            get => IfUndisposed(_SeedInterval);
            set
            {
                EnsureUndisposed();
                if (value == _SeedInterval) return;
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
                _SeedInterval = value;
                if (_Seeding == AutoSeedRngTypes.Interval) SeedTimeoutCancellation.Cancel();
            }
        }

        /// <summary>
        /// Last exception of the seeding background task
        /// </summary>
        public Exception? LastException { get; protected set; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            EnsureUndisposed();
            try
            {
                return Rng.FillBytes(buffer);
            }
            finally
            {
                SeedEvent.Set();
            }
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            try
            {
                return await Rng.FillBytesAsync(buffer, cancellationToken).DynamicContext();
            }
            finally
            {
                await SeedEvent.SetAsync(CancellationToken.None).DynamicContext();
            }
        }

        /// <inheritdoc/>
        public virtual void NextBytes(byte[] bytes)
        {
            EnsureUndisposed();
            Rng.NextBytes(bytes);
            SeedEvent.Set();
        }

        /// <inheritdoc/>
        public virtual void NextBytes(byte[] bytes, int start, int len)
        {
            EnsureUndisposed();
            Rng.NextBytes(bytes, start, len);
            SeedEvent.Set();
        }

        /// <inheritdoc/>
        public virtual void NextBytes(Span<byte> bytes)
        {
            EnsureUndisposed();
            Rng.NextBytes(bytes);
            SeedEvent.Set();
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed)
        {
            EnsureUndisposed();
            Rng.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            Rng.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed)
        {
            EnsureUndisposed();
            Rng.AddSeedMaterial(seed);
        }

        /// <inheritdoc/>
        public void AddSeed(ReadOnlySpan<byte> seed)
        {
            EnsureUndisposed();
            Rng.AddSeed(seed);
        }

        /// <inheritdoc/>
        public async Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            EnsureUndisposed();
            await Rng.AddSeedAsync(seed, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Background seeding
        /// </summary>
        protected virtual async Task SeedAsync()
        {
            await Task.Yield();
            byte[] buffer = new byte[SeedLength];
            try
            {
                while (EnsureUndisposed(throwException: false))
                {
                    switch (_Seeding)
                    {
                        case AutoSeedRngTypes.Interval:
                            try
                            {
                                await Task.Delay(_SeedInterval, SeedTimeoutCancellation.Token).DynamicContext();
                            }
                            catch (OperationCanceledException)
                            {
                                if (!IsDisposing) SeedTimeoutCancellation.TryReset();
                                continue;
                            }
                            break;
                        case AutoSeedRngTypes.AfterRndConsumed:
                            await SeedEvent.WaitAsync().DynamicContext();
                            if (_Seeding == AutoSeedRngTypes.Interval || IsDisposing) continue;
                            break;
                    }
                    await SeedProvider.FillBytesAsync(buffer).DynamicContext();
                    await Rng.AddSeedAsync(buffer).DynamicContext();
                    if (_Seeding == AutoSeedRngTypes.Permanent) continue;
                    if (_Seeding == AutoSeedRngTypes.AfterRndConsumed) await SeedEvent.ResetAsync();
                    await Rng.FillBytesAsync(buffer).DynamicContext();
                }
            }
            catch (ObjectDisposedException) when (IsDisposing)
            {
                try
                {
                    await Rng.FillBytesAsync(buffer).DynamicContext();
                }
                catch (Exception ex)
                {
                    LastException = ex;
                    RaiseOnSeedError();
                }
            }
            catch (Exception ex)
            {
                try
                {
                    await Rng.FillBytesAsync(buffer).DynamicContext();
                }
                catch (Exception ex2)
                {
                    ErrorHandling.Handle(new("RND buffer cleanup failed", ex2, Constants.CRYPTO_ERROR_SOURCE, this));
                }
                LastException = ex;
                RaiseOnSeedError();
                if (!IsDisposing) _ = DisposeAsync().AsTask();
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            SeedTimeoutCancellation.Cancel();
            SeedEvent.Set();
            SeedTask.GetAwaiter().GetResult();
            SeedEvent.Dispose();
            SeedTimeoutCancellation.Dispose();
            if (DisposeSeedProvider) SeedProvider.TryDispose();
            if (DisposeRng) Rng.TryDispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            SeedTimeoutCancellation.Cancel();
            await SeedEvent.SetAsync().DynamicContext();
            await SeedTask.DynamicContext();
            await SeedEvent.DisposeAsync().DynamicContext();
            SeedTimeoutCancellation.Dispose();
            if (DisposeSeedProvider) await SeedProvider.TryDisposeAsync().DynamicContext();
            if (DisposeRng) await Rng.TryDisposeAsync().DynamicContext();
        }

        /// <summary>
        /// Delegate for an <see cref="OnSeedError"/> event
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <param name="e">Arguments</param>
        public delegate void AutoSeedingRngEvent_Delegate(AutoSeedRng rng, EventArgs e);
        /// <summary>
        /// Raised on seed error (see <see cref="LastException"/>; this instance will be disposed after raising the event)
        /// </summary>
        public event AutoSeedingRngEvent_Delegate? OnSeedError;
        /// <summary>
        /// Raise the <see cref="OnSeedError"/> event
        /// </summary>
        protected virtual void RaiseOnSeedError() => OnSeedError?.Invoke(this, new());
    }
}
