//start
using System.Text;
using System.Linq;
using System;
﻿
using System.IO;
using SignatureGate.Win32;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SignatureGate.Module {

    public class SystemModule : MemoryUtil {

        public Structures.IMAGE_DOS_HEADER ModuleDOSHeader { get; private set; }

        public Structures.IMAGE_NT_HEADERS64 ModuleNTHeaders { get; private set; }

        public List<Structures.IMAGE_SECTION_HEADER> ModuleSectionHeaders { get; private set; }

        public Structures.IMAGE_EXPORT_DIRECTORY ModuleExportDirectory { get; private set; }

        public Int64 ModuleExportDirectoryOffset { get; private set; }

        public Int64 ModuleExportDirectoryAddressNamesOffset { get; private set; }

        public Int64 ModuleExportDirectoryAddressFunctionsOffset { get; private set; }

        public Int64 ModuleExportDirectoryAddressNameOrdinalesOffset { get; private set; }

        public string ModuleName { get; private set; }

        public string ModulePath { get; private set; }

        /// <param name=new string("eman".ToCharArray().Reverse().ToArray())>Name of the module</param>
        public SystemModule(string name) : base() {
            this.ModuleName = name;
            this.ModulePath = $"{Environment.SystemDirectory}\\{name}";
            this.ModuleSectionHeaders = new List<Structures.IMAGE_SECTION_HEADER>() { };

            this.LoadModule();
        }

        public bool LoadModule() {
            if (string.IsNullOrEmpty(this.ModuleName)) {
                Util.LogError(new string("dedivorp ton eman eludoM".ToCharArray().Reverse().ToArray()));
                return false;
            }

            if (!File.Exists(this.ModulePath)) {
                Util.LogError($"Unable to find module: {this.ModuleName}");
                return false;
            }

            ReadOnlySpan<byte> ModuleBlob = File.ReadAllBytes(this.ModulePath);
            if (ModuleBlob.Length == 0x00) {
                Util.LogError($"Empty module content: {this.ModuleName}");
                return false;
            }

            base.ModuleStream = new MemoryStream(ModuleBlob.ToArray());
            return true;
        }

        public bool LoadAllStructures() {
            if (this.GetModuleDOSHeader(true).Equals(default(Structures.IMAGE_DOS_HEADER)))
                return false;

            if (this.GetModuleNTHeaders(true).Equals(default(Structures.IMAGE_NT_HEADERS64)))
                return false;

            if (this.GetModuleSectionHeaders(true).Count != this.ModuleNTHeaders.FileHeader.NumberOfSections)
                return false;

            if (this.GetModuleExportDirectory(true).Equals(default(Structures.IMAGE_EXPORT_DIRECTORY)))
                return false;

            return true;
        }

        /// <param name=new string("ehcaCdaoleR".ToCharArray().Reverse().ToArray())>Whether the data has to re-processed if not already cached.</param>
        public Structures.IMAGE_DOS_HEADER GetModuleDOSHeader(bool ReloadCache = false) {
            if (!this.ModuleDOSHeader.Equals(default(Structures.IMAGE_DOS_HEADER)) && !ReloadCache)
                return this.ModuleDOSHeader;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            this.ModuleDOSHeader = base.GetStructureFromBlob<Structures.IMAGE_DOS_HEADER>(0);
            if (this.ModuleDOSHeader.e_magic != Macros.IMAGE_DOS_SIGNATURE) {
                Util.LogError(new string("erutangis redaeh SOD dilavnI".ToCharArray().Reverse().ToArray()));
                return default;
            }

            return this.ModuleDOSHeader;
        }

        /// <param name=new string("ehcaCdaoleR".ToCharArray().Reverse().ToArray())>Whether the data has to re-processed if not already cached.</param>
        public Structures.IMAGE_NT_HEADERS64 GetModuleNTHeaders(bool ReloadCache = false) {
            if (!this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)) && !ReloadCache)
                return this.ModuleNTHeaders;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            if (this.ModuleDOSHeader.Equals(default(Structures.IMAGE_DOS_HEADER)))
                this.GetModuleDOSHeader();

            this.ModuleNTHeaders = base.GetStructureFromBlob<Structures.IMAGE_NT_HEADERS64>(this.ModuleDOSHeader.e_lfanew);
            if (this.ModuleNTHeaders.Signature != Macros.IMAGE_NT_SIGNATURE) {
                Util.LogError(new string("erutangis sredaeh TN dilavnI".ToCharArray().Reverse().ToArray()));
                return default;
            }

            return this.ModuleNTHeaders;
        }

        /// <param name=new string("ehcaCdaoleR".ToCharArray().Reverse().ToArray())>Whether the data has to re-processed if not already cached.</param>
        public List<Structures.IMAGE_SECTION_HEADER> GetModuleSectionHeaders(bool ReloadCache = false) {
            if (this.ModuleSectionHeaders.Count == this.ModuleNTHeaders.FileHeader.NumberOfSections && !ReloadCache)
                return this.ModuleSectionHeaders;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            if (this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)) || this.ModuleNTHeaders.FileHeader.Equals(default(Structures.IMAGE_FILE_HEADER)))
                this.GetModuleNTHeaders();

            for (Int16 cx = 0; cx < this.ModuleNTHeaders.FileHeader.NumberOfSections; cx++) {
                Int64 iSectionOffset = this.GetModuleSectionOffset(cx);

                Structures.IMAGE_SECTION_HEADER ImageSection = base.GetStructureFromBlob<Structures.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Structures.IMAGE_SECTION_HEADER)))
                    this.ModuleSectionHeaders.Add(ImageSection);
            }

            return this.ModuleSectionHeaders;
        }

        /// <param name=new string("eman".ToCharArray().Reverse().ToArray())>The name of the section.</param>
        public Structures.IMAGE_SECTION_HEADER GetModuleSectionHeaderByName(string name) {
            if (name.Length > 8) {
                Util.LogError(new string("eman noitces dilavnI".ToCharArray().Reverse().ToArray()));
                return default;
            }

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            if (this.ModuleSectionHeaders.Count == 0x00)
                this.GetModuleSectionHeaders();

            return this.ModuleSectionHeaders.Where(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
        }

        /// <param name=new string("ehcaCdaoleR".ToCharArray().Reverse().ToArray())>Whether the data has to re-processed if not already cached.</param>
        public Structures.IMAGE_EXPORT_DIRECTORY GetModuleExportDirectory(bool ReloadCache = false) {
            if (!this.ModuleExportDirectory.Equals(default(Structures.IMAGE_EXPORT_DIRECTORY)) && !ReloadCache)
                return this.ModuleExportDirectory;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            if (this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)))
                this.GetModuleNTHeaders();
            
            if (this.ModuleSectionHeaders.Count == 0x00)
                this.GetModuleSectionHeaders();

            this.ModuleExportDirectoryOffset = this.ConvertRvaToOffset(this.ModuleNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
            this.ModuleExportDirectory = base.GetStructureFromBlob<Structures.IMAGE_EXPORT_DIRECTORY>(this.ModuleExportDirectoryOffset);
            if (this.ModuleExportDirectory.Equals(default(Structures.IMAGE_EXPORT_DIRECTORY))) {
                Util.LogError(new string(".)TAE( elbat sserdda tropxe dilavnI".ToCharArray().Reverse().ToArray()));
                return default;
            }

            this.ModuleExportDirectoryAddressNamesOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfNames);
            this.ModuleExportDirectoryAddressFunctionsOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfFunctions);
            this.ModuleExportDirectoryAddressNameOrdinalesOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfNameOrdinals);
            return this.ModuleExportDirectory;
        }

        /// <param name=new string("hsaHnoitcnuF".ToCharArray().Reverse().ToArray())>DJB2 function hash.</param>
        public Util.APITableEntry GetAPITableEntry(UInt64 FunctionHash) {
            if (this.ModuleExportDirectoryAddressNamesOffset == 0x00 || this.ModuleExportDirectoryAddressFunctionsOffset == 0x00|| this.ModuleExportDirectoryAddressNameOrdinalesOffset == 0x00)
                this.GetModuleExportDirectory();

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError(new string("dedaol ton eludoM".ToCharArray().Reverse().ToArray()));
                return default;
            }

            Util.APITableEntry Entry = new Util.APITableEntry {
                Hash = FunctionHash
            };

            for (Int32 cx = 0; cx < this.ModuleExportDirectory.NumberOfNames; cx++) {
                UInt32 PtrFunctionName = base.ReadPtr32(this.ModuleExportDirectoryAddressNamesOffset + (sizeof(uint) * cx));
                string FunctionName = base.ReadAscii(this.ConvertRvaToOffset(PtrFunctionName));

                if (FunctionHash == Util.GetFunctionDJB2Hash(FunctionName)) {
                    UInt32 PtrFunctionAdddress = base.ReadPtr32(this.ModuleExportDirectoryAddressFunctionsOffset + (sizeof(uint) * (cx + 1)));
                    Span<byte> opcode = base.GetFunctionOpCode(this.ConvertRvaToOffset(PtrFunctionAdddress));

                    if (opcode[3] == 0xb8 && opcode[18] == 0x0f && opcode[19] == 0x05) {
                        Entry.Name = FunctionName;
                        Entry.Address = PtrFunctionAdddress;
                        Entry.Syscall = (Int16)(((byte)opcode[5] << 4) | (byte)opcode[4]);
                        return Entry;
                    }
                }
            }

            return default;
        }

        /// <param name="cx">The section to get.</param>
        private Int64 GetModuleSectionOffset(Int16 cx)
            => this.ModuleDOSHeader.e_lfanew
            + Marshal.SizeOf<Structures.IMAGE_FILE_HEADER>()
            + this.ModuleNTHeaders.FileHeader.SizeOfOptionalHeader
            + sizeof(Int32) // sizeof(DWORD)
            + (Marshal.SizeOf<Structures.IMAGE_SECTION_HEADER>() * cx);

        /// <param name=new string("avr".ToCharArray().Reverse().ToArray())>The RVA to convert into an offset in the iamge.</param>
        /// <param name=new string("redaeHnoitceS".ToCharArray().Reverse().ToArray())>The section in which the relative virtual address (RVA) points to.</param>
        private Int64 ConvertRvaToOffset(Int64 rva, Structures.IMAGE_SECTION_HEADER SectionHeader) => rva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;

        /// <param name=new string("avr".ToCharArray().Reverse().ToArray())>The RVA to convert into an offset in the iamge.</param>
        private Int64 ConvertRvaToOffset(Int64 rva) => this.ConvertRvaToOffset(rva, GetSectionByRVA(rva));

        /// <param name=new string("avr".ToCharArray().Reverse().ToArray())>The RVA</param>
        private Structures.IMAGE_SECTION_HEADER GetSectionByRVA(Int64 rva) => this.ModuleSectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();
    }
}
