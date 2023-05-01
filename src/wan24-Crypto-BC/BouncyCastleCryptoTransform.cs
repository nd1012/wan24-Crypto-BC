using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle crypto transform
    /// </summary>
    public sealed class BouncyCastleCryptoTransform : DisposableBase, ICryptoTransform
    {
        /// <summary>
        /// Has the final block been transformed?
        /// </summary>
        private bool FinalBlockTransformed = false;
        /// <summary>
        /// Block cipher
        /// </summary>
        public readonly IBlockCipher? BlockCipher = null;
        /// <summary>
        /// Stream cipher
        /// </summary>
        public readonly IStreamCipher? StreamCipher = null;
        /// <summary>
        /// Digest
        /// </summary>
        public readonly IDigest? Digest = null;
        /// <summary>
        /// MAC
        /// </summary>
        public readonly IMac? Mac = null;

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
            CanReuseTransform = true;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="digest">Digest</param>
        public BouncyCastleCryptoTransform(IDigest digest) : base()
        {
            Digest = digest;
            InputBlockSize = digest.GetByteLength();
            OutputBlockSize = digest.GetDigestSize();
            CanTransformMultipleBlocks = false;
            CanReuseTransform = true;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="mac">MAC</param>
        public BouncyCastleCryptoTransform(IMac mac) : base()
        {
            Mac = mac;
            OutputBlockSize = InputBlockSize = mac.GetMacSize();
            CanTransformMultipleBlocks = false;
            CanReuseTransform = true;
        }

        /// <inheritdoc/>
        public bool CanReuseTransform { get; }

        /// <inheritdoc/>
        public bool CanTransformMultipleBlocks { get; }

        /// <inheritdoc/>
        public int InputBlockSize { get; }

        /// <inheritdoc/>
        public int OutputBlockSize { get; }

        /// <inheritdoc/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            EnsureUndisposed();
            if (StreamCipher != null)
            {
                StreamCipher.ProcessBytes(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
                return inputCount;
            }
            if (BlockCipher != null) return BlockCipher.ProcessBlock(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
            if (Digest != null)
            {
                Digest.BlockUpdate(inputBuffer.AsSpan(inputOffset, inputCount));
                return inputCount;
            }
            if (Mac != null)
            {
                Mac.BlockUpdate(inputBuffer.AsSpan(inputOffset, inputCount));
                return inputCount;
            }
            throw new InvalidProgramException();
        }

        /// <inheritdoc/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            EnsureUndisposed(allowDisposing: true);
            if (FinalBlockTransformed) throw new InvalidOperationException();
            if (StreamCipher != null)
            {
                if (inputCount == 0) return Array.Empty<byte>();
                using RentedArray<byte> outputBuffer = new(inputCount);
                int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
                byte[] res = used == 0 ? Array.Empty<byte>() : outputBuffer.Span[..used].ToArray();
                StreamCipher.Reset();
                return res;
            }
            if (BlockCipher != null)
            {
                if (inputCount == 0) return Array.Empty<byte>();
                using RentedArray<byte> outputBuffer = new(OutputBlockSize);
                int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
                byte[] res = used == 0 ? Array.Empty<byte>() : outputBuffer.Span[..used].ToArray();
                FinalBlockTransformed = true;
                Dispose();
                return res;
            }
            if (Digest != null)
            {
                TransformBlock(inputBuffer, inputOffset, inputCount, Array.Empty<byte>(), 0);
                byte[] res = new byte[OutputBlockSize];
                Digest.DoFinal(res);
                Digest.Reset();
                return res;
            }
            if (Mac != null)
            {
                TransformBlock(inputBuffer, inputOffset, inputCount, Array.Empty<byte>(), 0);
                byte[] res = new byte[OutputBlockSize];
                Mac.DoFinal(res);
                Mac.Reset();
                return res;
            }
            throw new InvalidProgramException();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (!FinalBlockTransformed) TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }
    }
}
