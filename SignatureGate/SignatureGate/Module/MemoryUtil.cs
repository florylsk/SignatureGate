//start
using System.Text;
using System.Linq;
using System;
﻿
using System.IO;
using System.Runtime.InteropServices;

namespace SignatureGate.Module {
    public class MemoryUtil : IDisposable {

        protected Stream ModuleStream { get; set; }

        ~MemoryUtil() => Dispose();

        public void Dispose() {
            this.ModuleStream.Dispose();
            this.ModuleStream.Close();
            GC.SuppressFinalize(this);
        }

        /// <typeparam name="T">The Type of the structure to extract.</typeparam>
        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The offset in the memory stream where the structure is located.</param>
        protected T GetStructureFromBlob<T>(Int64 offset) where T : struct {
            Span<byte> bytes = this.GetStructureBytesFromOffset<T>(offset);
            if (Marshal.SizeOf<T>() != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.Copy(bytes.ToArray(), 0, ptr, bytes.Length);
            T s = Marshal.PtrToStructure<T>(ptr);

            Marshal.FreeHGlobal(ptr);
            return s;
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the function in the memory stream.</param>
        protected Span<byte> GetFunctionOpCode(Int64 offset) {
            Span<byte> s = stackalloc byte[24];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the DWORD in the memory stream.</param>
        protected UInt32 ReadPtr32(Int64 offset) {
            Span<byte> s = stackalloc byte[4];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt32(s);
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the QWORD in the memory stream.</param>
        protected UInt64 ReadPtr64(Int64 offset) {
            Span<byte> s = stackalloc byte[8];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt64(s);
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the WORD in the memory stream.</param>
        protected UInt16 ReadUShort(Int64 offset) {
            Span<byte> s = stackalloc byte[2];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return BitConverter.ToUInt16(s);
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the ASCII string in the memory stream.</param>
        protected string ReadAscii(Int64 offset) {
            int length = 0;
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (this.ModuleStream.ReadByte() != 0x00)
                length++;

            Span<byte> s = length <= 1024 ? stackalloc byte[length] : new byte[length];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return Encoding.ASCII.GetString(s);
        }

        /// <typeparam name="T">The Type of the structure to extract from the memory stream.</typeparam>
        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the structure in the memory stream.</param>
        protected Span<byte> GetStructureBytesFromOffset<T>(Int64 offset) where T : struct {
            Span<byte> s = stackalloc byte[Marshal.SizeOf<T>()];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }

        /// <param name=new string("tesffo".ToCharArray().Reverse().ToArray())>The location of the bytes to extract from the memory stream.</param>
        /// <param name=new string("ezis".ToCharArray().Reverse().ToArray())>The number of bytes to extract from the memory stream at a give location.</param>
        protected Span<byte> GetBytesFromOffset(Int64 offset, int size) {
            Span<byte> s = size >= 1024 ? new byte[size] : stackalloc byte[size];
            this.ModuleStream.Seek(offset, SeekOrigin.Begin);
            this.ModuleStream.Read(s);
            return s.ToArray();
        }
    }
}
