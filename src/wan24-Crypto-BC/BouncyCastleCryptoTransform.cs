using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Bouncy Castle crypto transform
    /// </summary>
    public sealed class BouncyCastleCryptoTransform : ICryptoTransform
    {
        /// <summary>
        /// Block cipher
        /// </summary>
        public readonly IBlockCipher? BlockCipher = null;
        /// <summary>
        /// Stream cipher
        /// </summary>
        public readonly IStreamCipher? StreamCipher = null;
        /// <summary>
        /// Stream cipher
        /// </summary>
        public readonly IBufferedCipher? BufferedCipher = null;
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
        public BouncyCastleCryptoTransform(IBlockCipher cipher)
        {
            BlockCipher = cipher;
            OutputBlockSize = InputBlockSize = cipher.GetBlockSize();
            CanTransformMultipleBlocks = false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cipher">Cipher</param>
        public BouncyCastleCryptoTransform(IStreamCipher cipher)
        {
            StreamCipher = cipher;
            OutputBlockSize = InputBlockSize = 1;
            CanTransformMultipleBlocks = true;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cipher">Cipher</param>
        public BouncyCastleCryptoTransform(IBufferedCipher cipher)
        {
            BufferedCipher = cipher;
            OutputBlockSize = InputBlockSize = cipher.GetBlockSize();
            CanTransformMultipleBlocks = true;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="digest">Digest</param>
        public BouncyCastleCryptoTransform(IDigest digest)
        {
            Digest = digest;
            InputBlockSize = digest.GetByteLength();
            OutputBlockSize = digest.GetDigestSize();
            CanTransformMultipleBlocks = false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="mac">MAC</param>
        public BouncyCastleCryptoTransform(IMac mac)
        {
            Mac = mac;
            OutputBlockSize = InputBlockSize = mac.GetMacSize();
            CanTransformMultipleBlocks = false;
        }

        /// <inheritdoc/>
        public bool CanReuseTransform => false;

        /// <inheritdoc/>
        public bool CanTransformMultipleBlocks { get; }//TODO Determine how to transform multiple blocks

        /// <inheritdoc/>
        public int InputBlockSize { get; }

        /// <inheritdoc/>
        public int OutputBlockSize { get; }

        /// <inheritdoc/>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (StreamCipher is not null)
            {
                StreamCipher.ProcessBytes(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
                return inputCount;
            }
            if (BlockCipher is not null) return BlockCipher.ProcessBlock(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
            if (BufferedCipher is not null) return BufferedCipher.ProcessBytes(inputBuffer.AsSpan(inputOffset, inputCount), outputBuffer.AsSpan(outputOffset));
            if (Digest is not null)
            {
                Digest.BlockUpdate(inputBuffer.AsSpan(inputOffset, inputCount));
                inputBuffer.AsSpan(inputOffset, inputCount).CopyTo(outputBuffer.AsSpan(outputOffset));
                return inputCount;
            }
            if (Mac is not null)
            {
                Mac.BlockUpdate(inputBuffer.AsSpan(inputOffset, inputCount));
                inputBuffer.AsSpan(inputOffset, inputCount).CopyTo(outputBuffer.AsSpan(outputOffset));
                return inputCount;
            }
            throw new InvalidProgramException();
        }

        /// <inheritdoc/>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            try
            {
                if (StreamCipher is not null)
                {
                    if (inputCount == 0) return [];
                    using RentedArrayRefStruct<byte> outputBuffer = new(inputCount, clean: false)
                    {
                        Clear = true
                    };
                    int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer.Array, 0);
                    return used == 0 ? [] : outputBuffer.Span[..used].ToArray();
                }
                if (BlockCipher is not null)
                {
                    if (inputCount == 0) return [];
                    using RentedArrayRefStruct<byte> outputBuffer = new(Math.Max(inputCount, OutputBlockSize), clean: false)
                    {
                        Clear = true
                    };
                    int used = TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer.Array, 0);
                    return used == 0 ? [] : outputBuffer.Span[..used].ToArray();
                }
                if (BufferedCipher is not null) return BufferedCipher.DoFinal(inputBuffer, inputOffset, inputCount);
                if (Digest is not null)
                {
                    TransformBlock(inputBuffer, inputOffset, inputCount, [], 0);
                    byte[] res = new byte[OutputBlockSize];
                    Digest.DoFinal(res);
                    return res;
                }
                if (Mac is not null)
                {
                    TransformBlock(inputBuffer, inputOffset, inputCount, [], 0);
                    byte[] res = new byte[OutputBlockSize];
                    Mac.DoFinal(res);
                    return res;
                }
            }
            finally
            {
                Dispose();
            }
            throw new InvalidProgramException();
        }

        /// <inheritdoc/>
        public void Dispose() { }
    }
}
