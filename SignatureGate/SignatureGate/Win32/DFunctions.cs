//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Runtime.InteropServices;

namespace SignatureGate.Win32 {

    public class DFunctions {

        /// <param name=new string("eldnaHssecorP".ToCharArray().Reverse().ToArray())>A handle for the process for which the mapping should be done.</param>
        /// <param name=new string("sserddAesaB".ToCharArray().Reverse().ToArray())>A pointer to a variable that will receive the base address of the allocated region of pages.</param>
        /// <param name=new string("stiBoreZ".ToCharArray().Reverse().ToArray())>The number of high-order address bits that must be zero in the base address of the section view.</param>
        /// <param name=new string("eziSnoigeR".ToCharArray().Reverse().ToArray())>A pointer to a variable that will receive the actual size, in bytes, of the allocated region of pages.</param>
        /// <param name=new string("epyTnoitacollA".ToCharArray().Reverse().ToArray())>A bitmask containing flags that specify the type of allocation to be performed for the specified region of pages.</param>
        /// <param name=new string("tcetorP".ToCharArray().Reverse().ToArray())>A bitmask containing page protection flags that specify the protection desired for the committed region of pages.</param>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );

        /// <param name=new string("eldnaHssecorP".ToCharArray().Reverse().ToArray())>Handle to Process Object opened with PROCESS_VM_OPERATION access.</param>
        /// <param name=new string("sserddAesaB".ToCharArray().Reverse().ToArray())>Pointer to base address to protect. Protection will change on all page containing specified address. On output, BaseAddress will point to page start address.</param>
        /// <param name=new string("tcetorPoTsetyBfOrebmuN".ToCharArray().Reverse().ToArray())>Pointer to size of region to protect. On output will be round to page size (4KB).</param>
        /// <param name=new string("noitcetorPsseccAweN".ToCharArray().Reverse().ToArray())>One or some of PAGE_... attributes.</param>
        /// <param name=new string("noitcetorPsseccAdlO".ToCharArray().Reverse().ToArray())>Receive previous protection.</param>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 NewProtect,
            out UInt32 OldProtect
        );

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
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateThreadEx(
            ref IntPtr hThread,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
        );

        /// <param name=new string("eldnaHtcejbO".ToCharArray().Reverse().ToArray())>Open handle to a alertable executive object.</param>
        /// <param name=new string("elbatrelA".ToCharArray().Reverse().ToArray())>If set, calling thread is signaled, so all queued APC routines are executed.</param>
        /// <param name=new string("stuOemiT".ToCharArray().Reverse().ToArray())>Time-out interval, in microseconds. NULL means infinite.</param>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWaitForSingleObject(
            IntPtr ObjectHandle,
            bool Alertable,
            ref Structures.LARGE_INTEGER TimeOut
        );
    }
}
