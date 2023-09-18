using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// BouncyCastle HMAC algorithm
    /// </summary>
    internal sealed class BouncyCastleHmacAlgorithm : KeyedHashAlgorithm
    {
        /// <summary>
        /// MAC
        /// </summary>
        private readonly IMac Mac;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="mac">MAC</param>
        public BouncyCastleHmacAlgorithm(IMac mac) : base() => Mac = mac;

        /// <inheritdoc/>
        public override void Initialize() => Mac.Reset();

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize) => Mac.BlockUpdate(array.AsSpan(ibStart, cbSize));

        /// <inheritdoc/>
        protected override void HashCore(ReadOnlySpan<byte> source) => Mac.BlockUpdate(source);

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            byte[] res = new byte[Mac.GetMacSize()];
            Mac.DoFinal(res);
            return res;
        }

        /// <inheritdoc/>
        protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            try
            {
                bytesWritten = Mac.DoFinal(destination);
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
            Mac.Reset();
        }
    }
}
