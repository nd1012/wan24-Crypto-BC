using System.Collections.Concurrent;
using System.Reflection;
using wan24.Core;

namespace wan24.Crypto.BC
{
    /// <summary>
    /// Internal reflection extensions
    /// </summary>
    internal static class InternalReflectionExtensions
    {
        /// <summary>
        /// Private byte array fields (key is the type hash code)
        /// </summary>
        private static readonly ConcurrentDictionary<int, FieldInfo[]> Fields = new();

        /// <summary>
        /// Clear all private byte array fields
        /// </summary>
        /// <param name="obj">Object</param>
        internal static void ClearPrivateByteArrayFields(this object obj)
        {
            Type type = obj.GetType();
            int hashCode = type.GetHashCode();
            if (!Fields.TryGetValue(hashCode, out FieldInfo[]? fields))
            {
                Type baType = typeof(byte[]);
                fields = (from fi in type.GetFieldsCached(BindingFlags.Instance | BindingFlags.NonPublic)
                          where fi.FieldType == baType
                          select fi).ToArray();
                Fields.TryAdd(hashCode, fields);
            }
            for (int i = 0, len = fields.Length; i < len; (fields[i].GetValue(obj) as byte[])?.Clear(), i++) ;
        }
    }
}
