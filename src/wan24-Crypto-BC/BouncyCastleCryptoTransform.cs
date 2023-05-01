using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy castle crypto transform
    /// </summary>
    public sealed class BouncyCastleCryptoTransform : DisposableBase, ICryptoTransform
    {
        /// <summary>
        /// Block cipher
        /// </summary>
        private readonly IBlockCipher? BlockCipher = null;
        /// <summary>
        /// Stream cipher
        /// </summary>
        private readonly IStreamCipher? StreamCipher = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cipher">Cipher</param>
        public BouncyCastleCryptoTransform(IBlockCipher cipher) : base()
        {
            BlockCipher = cipher;
            OutputBlockSize = InputBlockSize = cipher.GetBlockSize();
            CanTransformMultipleBlocks = false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cipher">Cipher</param>
        public BouncyCastleCryptoTransform(IStreamCipher cipher) : base()
        {
            StreamCipher = cipher;
            OutputBlockSize = InputBlockSize = 1;
            CanTransformMultipleBlocks = true;
        }

        /// <inheritdoc/>
        public bool CanReuseTransform => false;

        /// <inheritdoc/>
        public bool CanTransformMultipleBlocks { get; }

        /// <inheritdoc/>
        public int InputBlockSize { get; }

        /// <inheritdoc/>
        public int OutputBlockSize { get; }

        /// <inheritdoc/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            StreamCipher?.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            return BlockCipher?.ProcessBlock(inputBuffer, inputOffset, outputBuffer, outputOffset) ?? inputCount;
        }

        /// <inheritdoc/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount == 0) return Array.Empty<byte>();
            using RentedArray<byte> outputBuffer = new(StreamCipher == null ? OutputBlockSize : inputCount);
            int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
            return used == 0 ? Array.Empty<byte>() : outputBuffer.Span[..used].ToArray();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) { }
    }
}
