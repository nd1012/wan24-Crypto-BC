using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using System.Reflection;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Private <see cref="VmpcRandomGenerator"/> <c>P</c> field name
        /// </summary>
        private const string P_FIELD = "P";
        /// <summary>
        /// Private <see cref="VmpcRandomGenerator"/> <c>s</c> field name
        /// </summary>
        private const string S_FIELD = "s";
        /// <summary>
        /// Private <see cref="VmpcRandomGenerator"/> <c>n</c> field name
        /// </summary>
        private const string N_FIELD = "n";

        /// <summary>
        /// <see cref="VmpcRandomGenerator"/> type
        /// </summary>
        private static readonly Type VmpcRandomGeneratorType = typeof(VmpcRandomGenerator);

        /// <summary>
        /// Get the internal state (you shouldn't add seed during this method is being executed!)
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <returns>Internal state</returns>
        public static byte[] GetState(this VmpcRandomGenerator rng)
        {
            byte[] p = (byte[])VmpcRandomGeneratorType.GetFieldCached(P_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Getter!(rng)!,
                res = new byte[p.Length + 2];
            lock (p)
            {
                p.AsSpan().CopyTo(res);
                p[^2] = (byte)VmpcRandomGeneratorType.GetFieldCached(S_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Getter!(rng)!;
                p[^1] = (byte)VmpcRandomGeneratorType.GetFieldCached(N_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Getter!(rng)!;
            }
            return res;
        }

        /// <summary>
        /// Restore the internal state (you shouldn't add seed during this method is being executed!)
        /// </summary>
        /// <param name="rng">RNG</param>
        /// <param name="state">Stored internal state</param>
        public static void RestoreState(this VmpcRandomGenerator rng, ReadOnlySpan<byte> state)
        {
            byte[] p = (byte[])VmpcRandomGeneratorType.GetFieldCached(P_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Getter!(rng)!;
            if (state.Length < p.Length + 2) throw new ArgumentOutOfRangeException(nameof(state));
            lock (p)
            {
                state[..p.Length].CopyTo(p);
                VmpcRandomGeneratorType.GetFieldCached(S_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Setter!(rng, state[p.Length]);
                VmpcRandomGeneratorType.GetFieldCached(N_FIELD, BindingFlags.NonPublic | BindingFlags.Instance)!.Setter!(rng, state[p.Length + 1]);
            }
        }

        /// <summary>
        /// Convert to <see cref="X25519PrivateKeyParameters"/>
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>X25519 private key</returns>
        public static X25519PrivateKeyParameters ToX25519PrivateKey(this Ed25519PrivateKeyParameters key)
        {
            using SecureByteArrayRefStruct data = new(key.GetEncoded());
            data[0] &= 248;
            data[31] &= 127;
            data[31] |= 64;
            return new(data.Array);
        }

        /// <summary>
        /// Convert to <see cref="X448PrivateKeyParameters"/>
        /// </summary>
        /// <param name="key">Private key</param>
        /// <returns>X448 private key</returns>
        public static X448PrivateKeyParameters ToX448PrivateKey(this Ed448PrivateKeyParameters key)
        {
            using SecureByteArrayRefStruct data = new(key.GetEncoded());
            data[0] &= 252;
            data[55] |= 128;
            using SecureByteArrayRefStruct convertedData = new(data.Span[0..56].ToArray());
            return new(convertedData.Array);
        }
    }
}
