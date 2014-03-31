namespace PEAnalyzer
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
        #region Fields

        private bool is32BitHeader;
        private IMAGE_DOS_HEADER dosHeader;
        private IMAGE_NT_HEADERS32 ntHeaders32;
        private IMAGE_NT_HEADERS64 ntHeaders64;
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32 { get { return ntHeaders32.OptionalHeader; } }
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64 { get { return ntHeaders64.OptionalHeader; } }
        private List<IMAGE_SECTION_HEADER> sectionHeaders = new List<IMAGE_SECTION_HEADER>();
        private byte[] code;
        private byte[] idata;
        private byte[] rdata;
        private List<DiscoveredString> discoveredStrings = new List<DiscoveredString>();
        private List<DiscoveredReference> discoveredReferences = new List<DiscoveredReference>();
        private ulong functionByteAlignment;

        #endregion

        #region Structures

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

        #endregion

        #region Enumerations

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

        #endregion

        #region Properties

        public ulong ImageBase
        {
            get
            {
                if (this.is32BitHeader)
                {
                    return optionalHeader32.ImageBase;
                }
                else
                {
                    return optionalHeader64.ImageBase;
                }
            }
        }

        public uint BaseOfCodeInMemory
        {
            get
            {
                if (this.is32BitHeader)
                {
                    return optionalHeader32.BaseOfCode;
                }
                else
                {
                    return optionalHeader64.BaseOfCode;
                }
            }
        }

        public uint SizeOfCode
        {
            get
            {
                if (this.is32BitHeader)
                {
                    return optionalHeader32.SizeOfCode;
                }
                else
                {
                    return optionalHeader64.SizeOfCode;
                }
            }
        }

        public uint BaseOfCodeInFile
        {
            get
            {
                if (this.is32BitHeader)
                {
                    return optionalHeader32.BaseOfCode;
                }
                else
                {
                    return optionalHeader64.BaseOfCode;
                }
            }
        }

        private uint NumberOfSections
        {
            get
            {
                if (this.is32BitHeader)
                {
                    return this.ntHeaders32.FileHeader.NumberOfSections;
                }
                else
                {
                    return this.ntHeaders64.FileHeader.NumberOfSections;
                }
            }
        }

        #endregion Properties

        #region Constructors

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
                this.code = new byte[this.SizeOfCode];
                fs.Seek(this.BaseOfCodeInFile, SeekOrigin.Begin);
                fs.Read(code, 0, this.code.Length);
            }
        }

        #endregion

        #region Methods

        private class AlignmentByteSequence
        {
            public AlignmentByteSequence(ulong offset, ulong length)
            {
                this.Offset = offset;
                this.Length = length;
            }

            public ulong Offset { get; private set; }

            public ulong Length { get; private set; }

            public ulong NextInstructionOffset
            {
                get
                {
                    return this.Offset + this.Length;
                }
            }
        }

        private class CodeChunk
        {
            public ulong Offset { get; private set; }

            public byte[] Code { get; private set; }

            public bool EndsOnAlignmentBoundary { get; private set; }

            public CodeChunk(ulong offset, ulong length, bool endsOnAlignmentBoundary)
            {
                this.Offset = offset;
                this.Code = new byte[length];
                this.EndsOnAlignmentBoundary = endsOnAlignmentBoundary;
            }
        }

        private HashSet<AlignmentByteSequence> CalculateByteAlignmentSequences()
        {
            if (this.code == null)
            {
                return new HashSet<AlignmentByteSequence>();
            }

            byte[] alignmentBytes = new byte[] { 0x90, 0xcc };
            ulong minimumByteSequenceLength = 1;
            HashSet<AlignmentByteSequence> alignmentSequences = new HashSet<AlignmentByteSequence>();

            for (ulong i = 0; i < (ulong)this.code.Length - minimumByteSequenceLength; ++i)
            {
                bool alignmentByteSequenceFound = true;

                // Scan the next 4 bytes;
                for (ulong j = 0; j < minimumByteSequenceLength; ++j)
                {
                    if (!alignmentBytes.Contains(this.code[i + j]))
                    {
                        alignmentByteSequenceFound = false;
                        break;
                    }
                }

                // Move to the next byte if no alignment byte sequence was found.
                if (!alignmentByteSequenceFound)
                {
                    continue;
                }

                ulong alignmentByteSequenceLength = 0;

                // See how long the alignment byte sequence is.
                for (ulong j = 0; j < (ulong)this.code.Length - minimumByteSequenceLength; ++j, ++alignmentByteSequenceLength)
                {
                    if (!alignmentBytes.Contains(this.code[i + j]))
                    {
                        break;
                    }
                }

                // Add the aligment byte sequence to the set of alignment byte sequences.
                alignmentSequences.Add(new AlignmentByteSequence(i, alignmentByteSequenceLength));

                // Advance the index to start right after the discovered byte sequence.
                i = i + alignmentByteSequenceLength;
            }

            // See if there are aligment bytes at the end of the code segment.
            int numEndingAlignmentBytes = this.code.Reverse().TakeWhile(x => alignmentBytes.Contains(x) || x == 0).Count();

            // If padding exists at the end, then add that as the final sequence.
            AlignmentByteSequence finalSequence = new AlignmentByteSequence((ulong)(this.code.Length - numEndingAlignmentBytes), (ulong)numEndingAlignmentBytes);
            alignmentSequences.Add(finalSequence);

            // Calculate the most likely alignment boundary.
            for (int i = 0; i < 64; ++i)
            {
                // Byte alignment values on Windows occur in values of a power of two, according to
                // http://msdn.microsoft.com/en-us/library/aa290049.aspx
                ulong thisPossibleAlignment = Convert.ToUInt64(Math.Pow(2, i));
                ulong nextPossibleAlignment = Convert.ToUInt64(Math.Pow(2, i + 1));

                int numThisAligment = alignmentSequences.Select(x => x.NextInstructionOffset % thisPossibleAlignment).Count(x => x == 0);
                int numNextAligment = alignmentSequences.Select(x => x.NextInstructionOffset % nextPossibleAlignment).Count(x => x == 0);

                int difference = Math.Abs(numThisAligment - numNextAligment);
                int average = (numThisAligment + numNextAligment) / 2;
                double percentDifference = (Convert.ToDouble(difference) / Convert.ToDouble(average)) * 100;

                // Set the threshhold of maximum difference to 45% difference. After that, it is likely that the
                // aligmnent boundary has been passed. 
                if (percentDifference > 45.0)
                {
                    this.functionByteAlignment = thisPossibleAlignment;
                    break;
                }
            }

            // If we were unable to determine the most likely byte alignment value, then use a standard Microsoft 16
            // byte aligment value.
            if (this.functionByteAlignment == 0)
            {
                this.functionByteAlignment = 16;
            }

            // Remove any aligment sequences that do not end on the aligment boundary.
            alignmentSequences.RemoveWhere(x => x.NextInstructionOffset % this.functionByteAlignment != 0);

            return alignmentSequences;
        }

        private HashSet<CodeChunk> GetCodeChunks(HashSet<AlignmentByteSequence> alignmentSequences)
        {
            HashSet<CodeChunk> codeChunks = new HashSet<CodeChunk>();

            // Get a list of all the code chunks.
            ulong currentOffset = 0;
            List<AlignmentByteSequence> orderedAligmentSequences = alignmentSequences.OrderBy(x => x.Offset).ToList();
            foreach (AlignmentByteSequence sequence in alignmentSequences.OrderBy(x => x.Offset))
            {
                // Copy the code to a code chunk.
                ulong codeChunkLength = sequence.Offset - currentOffset;
                bool endsOnAlignmentBoundary = ((currentOffset + codeChunkLength + 1) % this.functionByteAlignment) == 0;
                if (endsOnAlignmentBoundary)
                {
                    Console.WriteLine();
                }

                // TODO: ***IMPORTANT*** merge with next code chunk if this one ends on an alignment boundary.
                CodeChunk cc = new CodeChunk(currentOffset, codeChunkLength, endsOnAlignmentBoundary);
                Array.Copy(this.code, (long)currentOffset, cc.Code, 0, (long)codeChunkLength);
                codeChunks.Add(cc);

                // Set the next code offset.
                currentOffset = sequence.NextInstructionOffset;
            }

            return codeChunks;
        }

        private BasicBlock GetBasicBlockOrCreateNewBasicBlock(Dictionary<ulong, BasicBlock> basicBlocks, ulong address)
        {
            // See if the basic block already exists.
            if (basicBlocks.ContainsKey(address))
            {
                // If it already exists, then return it.
                return basicBlocks[address];
            }
            else
            {
                // Otherwise, create a new basic block, add it, and return it.
                BasicBlock bb = new BasicBlock(address);
                basicBlocks[address] = bb;
                return bb;
            }
        }

        // Add basic blocks based on control flow transitions.
        private void AddBasicBlocksFromInstructions(Dictionary<ulong, BasicBlock> basicBlocks, List<Instruction> instructions)
        {
            // Start the first basic block.
            BasicBlock bb = null;
            BasicBlock previousBasicBlock = null;

            // Set the first basic block to start with the first instruction in the instruction list.
            if (instructions.Count > 0)
            {
                bb = this.GetBasicBlockOrCreateNewBasicBlock(basicBlocks, instructions.First().Address);
            }
            else
            {
                return;
            }

            // Iterate through the instructions, adding to the current basic block and making new basic blocks as
            // necessary.
            bool lastInstructionWasConditionalBranch = false;
            foreach (Instruction i in instructions)
            {
                // Make a basic block for the instruction following a conditional branch.
                if (lastInstructionWasConditionalBranch)
                {
                    // Reset the flag.
                    lastInstructionWasConditionalBranch = false;

                    // Get the next basic block or create a new basic block.
                    previousBasicBlock = bb;
                    bb = this.GetBasicBlockOrCreateNewBasicBlock(basicBlocks, i.Address);

                    // Link the previous and current basic blocks.
                    previousBasicBlock.NextBasicBlocks.Add(bb);
                    bb.PreviousBasicBlocks.Add(previousBasicBlock);
                }

                if (i.FlowType == Instruction.ControlFlow.Call ||
                    i.FlowType == Instruction.ControlFlow.ConditionalBranch ||
                    i.FlowType == Instruction.ControlFlow.UnconditionalBranch)
                {
                    // Add a new basic block, based on the branch target, if it is not null. Start a new basic block.
                    if (i.BranchTarget != 0)
                    {
                        BasicBlock branchBlock = this.GetBasicBlockOrCreateNewBasicBlock(basicBlocks, i.BranchTarget);

                        if (i.FlowType == Instruction.ControlFlow.Call)
                        {
                            // Add the current instruction to the list of instructions that call the basic block
                            // located at the branch target.
                            branchBlock.CalledBy.Add(i);
                        }
                        else
                        {
                            // Link to the basic block located at the branch target.
                            bb.NextBasicBlocks.Add(branchBlock);
                            branchBlock.PreviousBasicBlocks.Add(bb);
                        }
                    }

                    // Set a flag so that the next instruction has a basic block created for it.
                    if (i.FlowType == Instruction.ControlFlow.ConditionalBranch)
                    {
                        lastInstructionWasConditionalBranch = true;
                    }
                }
            }
        }

        public void FindBasicBlocks()
        {
            // Get the aligment byte sequences, so that aligment bytes are not interpreted as code.
            HashSet<AlignmentByteSequence> alignmentSequences = this.CalculateByteAlignmentSequences();

            // Get the chunks of code, based off of the aligment sequences.
            HashSet<CodeChunk> codeChunks = this.GetCodeChunks(alignmentSequences);

            // Initialize the disassembler and tracking variables.
            Disassembler d = new Disassembler();
            d.Engine = Disassembler.InternalDisassembler.BeaEngine;
            d.TargetArchitecture = Disassembler.Architecture.x86_32;
            List<Instruction> instructions = new List<Instruction>();
            Dictionary<ulong, BasicBlock> basicBlocks = new Dictionary<ulong, BasicBlock>();

            // For each code chunk, disassemble it and find basic blocks.
            foreach (CodeChunk cc in codeChunks)
            {
                ulong virtualAddressBase = this.ImageBase + this.BaseOfCodeInMemory + cc.Offset;
                List<Instruction> codeChunkInstructions = new List<Instruction>(d.DisassembleInstructions(cc.Code, virtualAddressBase));

                // If no instructions were found or if the last instruction has no control flow, then it is likely
                // that decoding failed and that this is actually a data chunk.
                if (codeChunkInstructions.Count == 0 ||
                    !cc.EndsOnAlignmentBoundary && (codeChunkInstructions.Last().FlowType == Instruction.ControlFlow.None))
                {
                    // TODO: track data chunks.
                    continue;
                }
                else
                {
                    if (cc.EndsOnAlignmentBoundary && codeChunkInstructions.Last().FlowType == Instruction.ControlFlow.None)
                    {
                        Console.WriteLine();
                    }

                    // If the last instruction has some type of flow control, then it is likely that this code chunk
                    // was filled with valid code. Add all basic blocks from the disassembled list of instructions.
                    this.AddBasicBlocksFromInstructions(basicBlocks, codeChunkInstructions);

                    // Add instructions to the global list of instructions.
                    instructions.AddRange(codeChunkInstructions);
                }
            }

            // Iterate through all the verified valid instructions and add them to their respective basic blocks.
            BasicBlock currentBasicBlock = null;
            foreach (Instruction i in instructions)
            {
                if (basicBlocks.ContainsKey(i.Address))
                {
                    currentBasicBlock = basicBlocks[i.Address];
                }

                currentBasicBlock.Instructions.Add(i);
            }

            List<BasicBlock> sortedBasicBlocks = basicBlocks.Values.OrderBy(x => x.FirstInstructionAddress).ToList();

            Console.WriteLine();

            /*
            // Search for address references in rdata.
            IMAGE_SECTION_HEADER rdataSectionHeader = this.sectionHeaders.FirstOrDefault(x => x.Section.StartsWith(".rdata"));
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
            */
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

        #endregion
    }
}
