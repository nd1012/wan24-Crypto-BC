using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle hash algorithm
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="digest">Digest</param>
    public sealed class BouncyCastleHashAlgorithm(IDigest digest) : HashAlgorithm()
    {
        /// <summary>
        /// Digest
        /// </summary>
        private readonly IDigest Digest = digest;

        /// <inheritdoc/>
        public override int HashSize => Digest.GetDigestSize() << 3;

        /// <inheritdoc/>
        public override void Initialize() => Digest.Reset();

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize) => Digest.BlockUpdate(array.AsSpan(ibStart, cbSize));

        /// <inheritdoc/>
        protected override void HashCore(ReadOnlySpan<byte> source) => Digest.BlockUpdate(source);

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            byte[] res = new byte[Digest.GetDigestSize()];
            Digest.DoFinal(res);
            return res;
        }

        /// <inheritdoc/>
        protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            try
            {
                bytesWritten = Digest.DoFinal(destination);
                return true;
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            Digest.Reset();
        }
    }
}
