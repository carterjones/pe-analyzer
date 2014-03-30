﻿namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using Bunseki;

    class PEFile
    {
        private bool is32BitHeader;
        private IMAGE_DOS_HEADER dosHeader;
        private IMAGE_NT_HEADERS32 ntHeaders32;
        private IMAGE_NT_HEADERS64 ntHeaders64;
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32 { get { return ntHeaders32.OptionalHeader; } }
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64 { get { return ntHeaders64.OptionalHeader; } }
        private List<IMAGE_SECTION_HEADER> sectionHeaders = new List<IMAGE_SECTION_HEADER>();
        private byte[] idata;
        private byte[] rdata;
        private List<DiscoveredString> discoveredStrings = new List<DiscoveredString>();
        private List<DiscoveredReference> discoveredReferences = new List<DiscoveredReference>();

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;        // Bytes on last page of file
            public UInt16 e_cp;          // Pages in file
            public UInt16 e_crlc;        // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;          // Initial (relative) SS value
            public UInt16 e_sp;          // Initial SP value
            public UInt16 e_csum;        // Checksum
            public UInt16 e_ip;          // Initial IP value
            public UInt16 e_cs;          // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;        // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;      // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;      // Reserved words
            public Int32 e_lfanew;       // File address of new exe header
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public char[] Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public char[] Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        #region Properties

        public ulong? ImageBase
        {
            get
            {
                if (this.is32BitHeader)
                {
                    if (optionalHeader32.ImageBase != 0)
                    {
                        return optionalHeader32.ImageBase;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    if (optionalHeader64.ImageBase != 0)
                    {
                        return optionalHeader64.ImageBase;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        public uint? BaseOfCodeInMemory
        {
            get
            {
                if (this.is32BitHeader)
                {
                    if (optionalHeader32.BaseOfCode != 0)
                    {
                        return optionalHeader32.BaseOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    if (optionalHeader64.BaseOfCode != 0)
                    {
                        return optionalHeader64.BaseOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        public uint? SizeOfCode
        {
            get
            {
                if (this.is32BitHeader)
                {
                    if (optionalHeader32.SizeOfCode != 0)
                    {
                        return optionalHeader32.SizeOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    if (optionalHeader64.SizeOfCode != 0)
                    {
                        return optionalHeader64.SizeOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        public uint? BaseOfCodeInFile
        {
            get
            {
                if (this.is32BitHeader)
                {
                    if (optionalHeader32.BaseOfCode != 0)
                    {
                        return optionalHeader32.BaseOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    if (optionalHeader64.BaseOfCode != 0)
                    {
                        return optionalHeader64.BaseOfCode;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        private uint? NumberOfSections
        {
            get
            {
                if (this.is32BitHeader)
                {
                    if (this.ntHeaders32.FileHeader.NumberOfSections != 0)
                    {
                        return this.ntHeaders32.FileHeader.NumberOfSections;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    if (this.ntHeaders64.FileHeader.NumberOfSections != 0)
                    {
                        return this.ntHeaders64.FileHeader.NumberOfSections;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        #endregion Properties

        public PEFile(string filePath)
        {
            // Read in the PE File.
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                BinaryReader br = new BinaryReader(fs);

                // Read the DOS header.
                dosHeader = ReadToStruct<IMAGE_DOS_HEADER>(br);

                // Place the file stream at the beginning of the NT header.
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                // Read the NT header.
                UInt32 ntHeadersSignature = br.ReadUInt32();
                IMAGE_FILE_HEADER fileHeader = ReadToStruct<IMAGE_FILE_HEADER>(br);
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                this.is32BitHeader = (IMAGE_FILE_32BIT_MACHINE & fileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
                if (this.is32BitHeader)
                {
                    ntHeaders32 = ReadToStruct<IMAGE_NT_HEADERS32>(br);
                }
                else
                {
                    ntHeaders64 = ReadToStruct<IMAGE_NT_HEADERS64>(br);
                }

                // Read the section headers.
                for (int i = 0; i < this.NumberOfSections; ++i)
                {
                    IMAGE_SECTION_HEADER sectionHeader = ReadToStruct<IMAGE_SECTION_HEADER>(br);
                    this.sectionHeaders.Add(sectionHeader);
                }

                // Read the .rdata section.
                IMAGE_SECTION_HEADER rdataSectionHeader = this.sectionHeaders.FirstOrDefault(x => x.Section.StartsWith(".rdata"));
                if (rdataSectionHeader.SizeOfRawData != 0)
                {
                    // Allocate .idata and .rdata byte arrays.
                    if (this.is32BitHeader)
                    {
                        this.idata = new byte[ntHeaders32.OptionalHeader.IAT.Size];
                    }
                    else
                    {
                        this.idata = new byte[ntHeaders64.OptionalHeader.IAT.Size];
                    }

                    this.rdata = new byte[rdataSectionHeader.SizeOfRawData - this.idata.Length];

                    // Move the file stream reader to the .rdata Section.
                    fs.Seek(rdataSectionHeader.PointerToRawData, SeekOrigin.Begin);
                    fs.Read(this.idata, 0, this.idata.Length);
                    fs.Read(this.rdata, 0, this.rdata.Length);
                }

                // Read the code segment to a byte array.
                ulong imageBase = this.ImageBase ?? 0;
                uint baseOfCode = this.BaseOfCodeInMemory ?? 0;
                uint sizeOfCode = this.SizeOfCode ?? 0;
                byte[] code = new byte[sizeOfCode];
                fs.Seek(baseOfCode, SeekOrigin.Begin);
                fs.Read(code, 0, (int)sizeOfCode);

                // Disassemble the code segment.
                Disassembler d = new Disassembler();
                d.Engine = Disassembler.InternalDisassembler.BeaEngine;
                d.TargetArchitecture = Disassembler.Architecture.x86_32;
                ulong codeVirtualBaseAddress = imageBase + baseOfCode;
                HashSet<Instruction> instructions = new HashSet<Instruction>(
                    d.DisassembleInstructions(code, codeVirtualBaseAddress));

                ////////////////////////////////
                // Find all the basic blocks. //
                ////////////////////////////////
                HashSet<BasicBlock> basicBlocks = new HashSet<BasicBlock>();
                BasicBlock bb = new BasicBlock();

                // TODO: make a basic block for instructions following a conditional jump.

                // Add basic blocks based on control flow transitions.
                bool lastInstructionWasConditionalBranch = false;
                foreach (Instruction i in instructions)
                {
                    // Make a basic block for the instruction following a conditional branch.
                    if (lastInstructionWasConditionalBranch)
                    {
                        // Reset the flag.
                        lastInstructionWasConditionalBranch = false;

                        // Add the basic block.
                        bb = new BasicBlock();
                        bb.FirstInstructionAddress = i.Address;
                        basicBlocks.Add(bb);
                    }

                    if (i.FlowType == Instruction.ControlFlow.Call ||
                        i.FlowType == Instruction.ControlFlow.ConditionalBranch ||
                        i.FlowType == Instruction.ControlFlow.UnconditionalBranch)
                    {
                        // Add the branch target as the start of a basic block if the address is not zero.
                        if (i.BranchTarget != 0)
                        {
                            bb = new BasicBlock();
                            bb.FirstInstructionAddress = i.BranchTarget;
                            basicBlocks.Add(bb);
                        }

                        // Set a flag so that the next instruction has a basic block created for it.
                        if (i.FlowType == Instruction.ControlFlow.ConditionalBranch)
                        {
                            lastInstructionWasConditionalBranch = true;
                        }
                    }
                }

                // Search for address references in rdata.
                int addressSize = this.is32BitHeader ? 4 : 8;
                byte[] addressBytes = new byte[addressSize];
                HashSet<uint> instructionAddressesAsUInt = new HashSet<uint>(instructions.Select(x => (uint)x.Address));
                HashSet<ulong> instructionAddressesAsULong = new HashSet<ulong>(instructions.Select(x => x.Address));
                for (int i = 0; i < this.rdata.Length - addressSize; ++i)
                {
                    // Convert the byte aray to an address.
                    Array.Copy(this.rdata, i, addressBytes, 0, addressSize);
                    if (this.is32BitHeader)
                    {
                        uint address32 = BitConverter.ToUInt32(addressBytes, 0);

                        // Check to see if the address exists in the list of disassembled instructions.
                        // If it does exist,
                        //   1 - add the reference to the list of discovered references.
                        //   2 - use the address to create a new basic block if it does not exist.
                        if (instructionAddressesAsUInt.Contains(address32))
                        {
                            DiscoveredReference dr = new DiscoveredReference();
                            dr.Address = (ulong)(rdataSectionHeader.VirtualAddress + this.idata.Length + i);
                            dr.RawBytes = new byte[addressSize];
                            Array.Copy(addressBytes, dr.RawBytes, addressSize);
                            this.discoveredReferences.Add(dr);

                            bb = new BasicBlock();
                            bb.FirstInstructionAddress = address32;
                            basicBlocks.Add(bb);
                        }
                    }
                    else
                    {
                        ulong address64 = (ulong)BitConverter.ToInt64(addressBytes, 0);

                        // Check to see if the address exists in the list of disassembled instructions.
                        // If it does exist,
                        //   1 - add the reference to the list of discovered references.
                        //   2 - use the address to create a new basic block if it does not exist.
                        if (instructionAddressesAsULong.Contains(address64))
                        {
                            DiscoveredReference dr = new DiscoveredReference();
                            dr.Address = (ulong)(rdataSectionHeader.VirtualAddress + this.idata.Length + i);
                            dr.RawBytes = new byte[addressSize];
                            Array.Copy(addressBytes, dr.RawBytes, addressSize);
                            this.discoveredReferences.Add(dr);

                            bb = new BasicBlock();
                            bb.FirstInstructionAddress = address64;
                            basicBlocks.Add(bb);
                        }
                    }
                }

                // TODO: see why some basic blocks occur outside of the premissible range of addresses.

                // Get the last instruction found in the code section.
                List<Instruction> sortedInstructions = instructions.OrderBy(x => x.Address).ToList();
                Instruction firstInstruction = sortedInstructions.FirstOrDefault();
                Instruction lastInstruction = sortedInstructions.LastOrDefault();
                ulong firstPermissibleAddress = (ulong)firstInstruction.Address;
                ulong lastPermissibleAddress = (ulong)lastInstruction.Address;

                // Create a sorted list of basic blocks for iteration purposes. Only use basic blocks that are valid
                // (occur at or after the first instruction and start before the last instruction).
                List<BasicBlock> sortedBasicBlocks = basicBlocks
                    .Where(x => (x.FirstInstructionAddress < lastPermissibleAddress) &&
                                (x.FirstInstructionAddress >= firstPermissibleAddress))
                    .OrderBy(x => x.FirstInstructionAddress)
                    .ToList();

                // TODO: make sure all previous basic blocks are connected.
                // TODO: make sure all next basic blocks are connected.
                // x 1 - Make sure all basic blocks ending with conditional branch instructions have at least two next basic blocks.
                // o 2 - Make sure all basic blocks ending with return instructions have no basic blocks. This should be automatic.
                // o 3 - Make sure all basic blocks ending with unconditional branch instructions have only one next basic block.

                // Add each instruction to the basic blocks.
                int currentBasicBlockIndex = 0;
                BasicBlock currentBasicBlock = new BasicBlock();
                BasicBlock nextBasicBlock = new BasicBlock();
                if (sortedBasicBlocks.Count > 0)
                {
                    currentBasicBlock = sortedBasicBlocks[currentBasicBlockIndex];
                    Instruction instruction = Instruction.CreateInvalidInstruction();
                    for (int i = 0; i < sortedInstructions.Count; ++i)
                    {
                        instruction = sortedInstructions[i];

                        if (instruction.Address == 0x00428b07)
                        {
                            Console.WriteLine();
                        }

                        // If the instruction occurs before the current basic block, ignore it.
                        if (instruction.Address < currentBasicBlock.FirstInstructionAddress)
                        {
                            continue;
                        }

                        // Check to see if another basic block exists.
                        if (currentBasicBlockIndex + 1 < sortedBasicBlocks.Count)
                        {
                            nextBasicBlock = sortedBasicBlocks[currentBasicBlockIndex + 1];
                            ulong nextBasicBlockAddress = nextBasicBlock.FirstInstructionAddress;

                            // If the current instruction equals the address of the next basic block, then move to that block.
                            if (nextBasicBlockAddress == instruction.Address)
                            {
                                currentBasicBlock = nextBasicBlock;
                                currentBasicBlockIndex++;
                            }
                        }

                        // Check to see if the basic block's instruction list is empty.
                        if (currentBasicBlock.Instructions.Count == 0)
                        {
                            // If the current instruction equals the expected first instruction of the basic block,
                            // then add the instruction.
                            if (currentBasicBlock.FirstInstructionAddress == instruction.Address)
                            {
                                // Add the instruction to the basic block.
                                currentBasicBlock.Instructions.Add(instruction);
                            }
                            else
                            {
                                // Check for decoding errors.
                                ulong correctFirstInstructionAddress = currentBasicBlock.FirstInstructionAddress;
                                ulong incorrectFirstInstructionAddress = instruction.Address;
                                const ulong MAX_NUMBER_OF_BYTES_IN_X86_INSTRUCTION = 14;
                                ulong addressDifference = incorrectFirstInstructionAddress - correctFirstInstructionAddress;

                                // If the difference in addresses of the correct first instruction and incorrect
                                // is less than the maximum number of bytes in an x86 instruction, then the error could be
                                // caused by data within the code segment.
                                if (addressDifference <= MAX_NUMBER_OF_BYTES_IN_X86_INSTRUCTION)
                                {
                                    // Calculate the code offset.
                                    int correctOffset = (int)(correctFirstInstructionAddress - codeVirtualBaseAddress);

                                    // Copy a portion of the code into a temporary buffer.
                                    byte[] codeSubset = new byte[MAX_NUMBER_OF_BYTES_IN_X86_INSTRUCTION * 2];
                                    Array.Copy(code, correctOffset, codeSubset, 0, (int)MAX_NUMBER_OF_BYTES_IN_X86_INSTRUCTION * 2);

                                    // Re-disassemble the bytes to get a correct result.
                                    List<Instruction> reDisassembledInstructions = new List<Instruction>(
                                        d.DisassembleInstructions(codeSubset, currentBasicBlock.FirstInstructionAddress));

                                    foreach (Instruction newInstruction in reDisassembledInstructions)
                                    {
                                        ulong newInstructionAddress = newInstruction.Address;

                                        if (newInstructionAddress < incorrectFirstInstructionAddress)
                                        {
                                            // If this instruction comes before the incorrect instruction, then add it.
                                            currentBasicBlock.Instructions.Add(newInstruction);
                                        }
                                        else if (newInstructionAddress == incorrectFirstInstructionAddress)
                                        {
                                            // If this instruction occurs at the address of the incorrect instruction,
                                            // add the newly disassembled version of the instruction and stop adding
                                            // more instructions.
                                            currentBasicBlock.Instructions.Add(newInstruction);
                                            break;
                                        }
                                        else
                                        {
                                            throw new Exception("An unknown situation occured while redisassembling some code.");
                                        }
                                    }
                                }
                                else
                                {
                                    // See if a valid instruction does exist at this address.
                                    Instruction correctInstruction = Instruction.CreateInvalidInstruction();

                                    bool foundValidInstruction = false;

                                    // Find the correct instruction.
                                    while (!foundValidInstruction)
                                    {
                                        correctInstruction = sortedInstructions.FirstOrDefault(x => x.Address == currentBasicBlock.FirstInstructionAddress);

                                        if (correctInstruction == null)
                                        {
                                            // No instruction exists, so we assume the basic block has been invalidly created.
                                            if (!basicBlocks.Remove(currentBasicBlock))
                                            {
                                                throw new Exception("Could not remove invalid basic block.");
                                            }

                                            if (currentBasicBlockIndex >= basicBlocks.Count)
                                            {
                                                throw new Exception("No more basic blocks exist.");
                                            }

                                            // Create a new sorted basic block list.
                                            sortedBasicBlocks = basicBlocks.OrderBy(x => x.FirstInstructionAddress).ToList();

                                            // Set a new current basic block.
                                            currentBasicBlock = sortedBasicBlocks[currentBasicBlockIndex];

                                            correctInstruction = sortedInstructions.FirstOrDefault(x => (ulong)x.Address == currentBasicBlock.FirstInstructionAddress);
                                            if (correctInstruction == null)
                                            {
                                                continue;
                                            }
                                            else
                                            {
                                                foundValidInstruction = true;
                                            }
                                        }
                                        else
                                        {
                                            // TODO: Handle this error.
                                            Console.WriteLine("current basic block: 0x" + new IntPtr((long)currentBasicBlock.FirstInstructionAddress).ToString("x"));
                                            Console.WriteLine("current instruction: " + instruction.AddressAsString);
                                            Console.WriteLine();

                                            continue;
                                        }
                                    }

                                    // See if previous basic blocks used this instruction and remove the instruction,
                                    // as well as any subsequent instructions, from that basic block.
                                    IEnumerable<BasicBlock> basicBlocksWithCorrectInstruction = 
                                        sortedBasicBlocks.Where(x => x.Instructions.Contains(correctInstruction));
                                    if (basicBlocksWithCorrectInstruction.Count() > 1)
                                    {
                                        throw new Exception("TODO: handle the case where more than one basic block has the correct instruction.");
                                    }

                                    // Only keep the instructions belonging to each basic block containing the
                                    // correct instruction.
                                    foreach (BasicBlock bbToBeCorrected in basicBlocksWithCorrectInstruction)
                                    {
                                        int indexOfCorrectInstruction = bbToBeCorrected.Instructions.IndexOf(correctInstruction);
                                        List<Instruction> correctInstructions = bbToBeCorrected.Instructions.Take(indexOfCorrectInstruction).ToList();
                                        bbToBeCorrected.Instructions.Clear();
                                        bbToBeCorrected.Instructions.AddRange(correctInstructions);
                                    }

                                    // Add the correct instruction to the current basic block.
                                    currentBasicBlock.Instructions.Add(correctInstruction);
                                }
                            }
                        }
                        else
                        {
                            // Add the next basic block.
                            currentBasicBlock.Instructions.Add(instruction);
                        }

                        if ((ulong)currentBasicBlock.Instructions.FirstOrDefault().Address != currentBasicBlock.FirstInstructionAddress)
                        {
                            Console.WriteLine();
                        }

                        // If the instruction is a control flow changing instruction, move to the next basic block.
                        // Do not count call instructions as a flow changing instruction.
                        if (instruction.FlowType == Instruction.ControlFlow.ConditionalBranch ||
                            instruction.FlowType == Instruction.ControlFlow.UnconditionalBranch ||
                            instruction.FlowType == Instruction.ControlFlow.Return)
                        {
                            // Check to see if another basic block exists.
                            if (currentBasicBlockIndex + 1 >= sortedBasicBlocks.Count)
                            {
                                // Exit the loop if no more basic blocks remain.
                                break;
                            }

                            nextBasicBlock = sortedBasicBlocks[currentBasicBlockIndex + 1];

                            // Link to the fall-through basic block, for when the conditional branch is false.
                            if (instruction.FlowType == Instruction.ControlFlow.ConditionalBranch)
                            {
                                currentBasicBlock.NextBasicBlocks.Add(nextBasicBlock);
                                nextBasicBlock.PreviousBasicBlocks.Add(currentBasicBlock);
                            }

                            // Move to the next basic block.
                            currentBasicBlock = nextBasicBlock;
                            currentBasicBlockIndex++;
                        }
                    }
                }

                basicBlocks = new HashSet<BasicBlock>(sortedBasicBlocks);

                Instruction testInst = instructions.FirstOrDefault(x => x.Address == 0x004c50b2);
                BasicBlock test = basicBlocks.FirstOrDefault(x => x.FirstInstructionAddress == 0x004c50b2);

                // Link all basic blocks that change control flow because of a conditional or unconditional branch.
                BasicBlock branchTargetBlock = new BasicBlock();
                foreach (BasicBlock block in basicBlocks)
                {
                    lastInstruction = block.Instructions.LastOrDefault();

                    if (lastInstruction.FlowType == Instruction.ControlFlow.ConditionalBranch ||
                        lastInstruction.FlowType == Instruction.ControlFlow.UnconditionalBranch)
                    {
                        // Find the matching basic block that this basic block can branch to.
                        branchTargetBlock = basicBlocks.FirstOrDefault(x => x.FirstInstructionAddress.Equals(lastInstruction.BranchTarget));

                        if (branchTargetBlock != null)
                        {
                            // Link it with this basic block.
                            block.NextBasicBlocks.Add(branchTargetBlock);
                            branchTargetBlock.PreviousBasicBlocks.Add(block);
                        }
                        else
                        {
                            // Cannot link a non-deterministic branch.
                        }
                    }
                }

                // Basic block processing is complete at this point.

                BasicBlock lastBasicBlock = sortedBasicBlocks.LastOrDefault();
                List<ulong> endAddresses = sortedBasicBlocks.Skip(1).Select(x => x.FirstInstructionAddress).ToList();

                Console.WriteLine();
            }
        }

        private IEnumerator<BasicBlock> GetNextBasicBlock(IEnumerable<BasicBlock> basicBlocks)
        {
            foreach (BasicBlock bb in basicBlocks)
            {
                yield return bb;
            }
        }

        // Reads in a block from a binary stream and converts it to the struct type specified by the template parameter.
        public static T ReadToStruct<T>(BinaryReader reader)
        {
            // Read in a byte array.
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, and then unpin it.
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public struct DiscoveredString
        {
            public byte[] RawBytes;
            public ulong Address;
            public Encoding Encoding;

            public string StringFormat
            {
                get
                {
                    if (this.RawBytes == null || this.Address == 0 || this.Encoding == null)
                    {
                        return string.Empty;
                    }

                    return this.Encoding.GetString(this.RawBytes, 0, this.RawBytes.Length);
                }
            }
        }

        public struct DiscoveredReference
        {
            public byte[] RawBytes;
            public ulong Address;
            public ulong ReferencedAddress
            {
                get
                {
                    ulong address = 0;
                    if (this.RawBytes.Length == 4)
                    {
                        address += BitConverter.ToUInt32(this.RawBytes, 0);
                    }
                    else
                    {
                        address += BitConverter.ToUInt64(this.RawBytes, 0);
                    }

                    return address;
                }
            }
        }
    }
}
