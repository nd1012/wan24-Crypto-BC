namespace wan24.Crypto.BC
{
    /// <summary>
    /// XSalsa20 CSRNG
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">Internal RNG to use (will be disposed, if possible!)</param>
    /// <param name="bufferSize">Buffer size in bytes (min. <see cref="EncryptionXSalsa20Algorithm.IV_SIZE"/>)</param>
    /// <param name="seedLength">Seed the given RNG with N byte from <see cref="RND"/> (skipped, if <see langword="null"/> or <c>&lt;1</c>)</param>
    public sealed class XSalsa20Rng(in ISeedableRng? rng = null, in int? bufferSize = null, in int? seedLength = 256)
        : StreamCipherRng(EncryptionXSalsa20Algorithm.Instance, rng, bufferSize, seedLength)
    {
    }
}
