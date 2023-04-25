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
        /// Cipher
        /// </summary>
        private readonly IBlockCipher Cipher;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cipher">Cipher</param>
        public BouncyCastleCryptoTransform(IBlockCipher cipher) : base() => Cipher = cipher;

        /// <inheritdoc/>
        public bool CanReuseTransform => false;

        /// <inheritdoc/>
        public bool CanTransformMultipleBlocks => false;

        /// <inheritdoc/>
        public int InputBlockSize => Cipher.GetBlockSize();

        /// <inheritdoc/>
        public int OutputBlockSize => Cipher.GetBlockSize();

        /// <inheritdoc/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            => Cipher.ProcessBlock(inputBuffer, inputOffset, outputBuffer, outputOffset);

        /// <inheritdoc/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            using RentedArray<byte> outputBuffer = new(OutputBlockSize);
            int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
            return outputBuffer.Span[..used].ToArray();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) { }
    }
}
