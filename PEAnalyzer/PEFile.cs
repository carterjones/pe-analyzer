﻿namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using BeaEngineCS;

    using Disasm = BeaEngineCS.BeaEngine._Disasm;

    /// <summary>
    /// Represents a PE file. Contains information about the file and can be used for extracting data from the file.
    /// </summary>
    public class PEFile
    {
        #region Fields

        /// <summary>
        /// The maximum number of bytes in an x86 instruction.
        /// </summary>
        private const ulong MaxNumberOfBytesInX86Instruction = 15;

        /// <summary>
        /// A flag indicating whether or not this PE file has a 32-bit header.
        /// </summary>
        private bool is32BitHeader;

        /// <summary>
        /// The DOS header of the PE file.
        /// </summary>
        private IMAGE_DOS_HEADER dosHeader;

        /// <summary>
        /// A 32-bit version of the NT headers. Check is32BitHeader to determine if this or ntHeaders64 should be used.
        /// </summary>
        private IMAGE_NT_HEADERS32 ntHeaders32;

        /// <summary>
        /// A 64-bit version of the NT headers. Check is32BitHeader to determine if this or ntHeaders32 should be used.
        /// </summary>
        private IMAGE_NT_HEADERS64 ntHeaders64;

        /// <summary>
        /// A list of the section headers in this PE file.
        /// </summary>
        private List<IMAGE_SECTION_HEADER> sectionHeaders = new List<IMAGE_SECTION_HEADER>();

        /// <summary>
        /// The byte array representing the code segment.
        /// </summary>
        private byte[] code;

        /// <summary>
        /// The byte array representing the .idata section.
        /// </summary>
        private byte[] idata;

        /// <summary>
        /// The byte array representing the .rdata section.
        /// </summary>
        private byte[] rdata;

        private ByteType[] byteTypes;

        /// <summary>
        /// The bytes used for aligning functions and data against alignment boundaries.
        /// </summary>
        private byte[] alignmentBytes = new byte[] { 0x90, 0xcc };

        private ulong firstUnprocessedCodeOffset;

        #endregion

        #region Enumerations

        private enum ByteType : byte
        {
            Unprocessed = 0,
            ExpectedInstructionStart,
            InstructionStart,
            InstructionPart,
            AlignmentByte,
            JumpTableAddressStart,
            JumpTableAddressPart,
            MultiByteNopStart,
            MultiByteNopPart,
            ArbitraryDataStart,
            ArbitraryDataPart
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the PEFile class. Reads the file and parses the file structure.
        /// </summary>
        /// <param name="filePath">a file path to the location of the PE file</param>
        public PEFile(string filePath)
        {
            // Initialize properties.
            this.BasicBlocks = new Dictionary<ulong, BasicBlock>();
            this.Instructions = new Dictionary<ulong, Disasm>();
            this.Functions = new Dictionary<ulong, Function>();

            // Read in the PE File.
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                BinaryReader br = new BinaryReader(fs);

                // Read the DOS header.
                this.dosHeader = ReadToStruct<IMAGE_DOS_HEADER>(br);

                // Place the file stream at the beginning of the NT header.
                fs.Seek(this.dosHeader.e_lfanew, SeekOrigin.Begin);

                // Read the NT header.
                uint ntHeadersSignature = br.ReadUInt32();
                IMAGE_FILE_HEADER fileHeader = ReadToStruct<IMAGE_FILE_HEADER>(br);
                fs.Seek(this.dosHeader.e_lfanew, SeekOrigin.Begin);
                this.is32BitHeader = fileHeader.Characteristics.HasFlag(IFHCharacteristics.IMAGE_FILE_32BIT_MACHINE);
                if (this.is32BitHeader)
                {
                    this.ntHeaders32 = ReadToStruct<IMAGE_NT_HEADERS32>(br);
                }
                else
                {
                    this.ntHeaders64 = ReadToStruct<IMAGE_NT_HEADERS64>(br);
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
                        this.idata = new byte[this.ntHeaders32.OptionalHeader.IAT.Size];
                    }
                    else
                    {
                        this.idata = new byte[this.ntHeaders64.OptionalHeader.IAT.Size];
                    }

                    this.rdata = new byte[rdataSectionHeader.SizeOfRawData - this.idata.Length];

                    // Move the file stream reader to the .rdata Section.
                    fs.Seek(rdataSectionHeader.PointerToRawData, SeekOrigin.Begin);
                    fs.Read(this.idata, 0, this.idata.Length);
                    fs.Read(this.rdata, 0, this.rdata.Length);
                }

                // Read the code segment to a byte array.
                this.code = new byte[this.SizeOfCode];
                this.byteTypes = Enumerable.Repeat(ByteType.Unprocessed, (int)this.SizeOfCode).ToArray();
                fs.Seek(this.BaseOfCodeInFile, SeekOrigin.Begin);
                fs.Read(this.code, 0, this.code.Length);
            }
        }

        #endregion

        #region Enumerations

        /// <summary>
        /// The architecture type of the computer.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented", Justification = "Using Microsoft fields.")]
        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }

        /// <summary>
        /// The state of the image file.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented", Justification = "Using Microsoft fields.")]
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        /// <summary>
        /// The subsystem required to run this image.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented", Justification = "Using Microsoft fields.")]
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

        /// <summary>
        /// The DLL characteristics of the image.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented", Justification = "Using Microsoft fields.")]
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

        /// <summary>
        /// The characteristics of the image.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented", Justification = "Using Microsoft fields.")]
        public enum IFHCharacteristics : ushort
        {
            IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
            IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
            IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
            IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
            IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
            IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
            IMAGE_FILE_32BIT_MACHINE = 0x0100,
            IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
            IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
            IMAGE_FILE_SYSTEM = 0x1000,
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
            IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
        }

        /// <summary>
        /// The characteristics of the image.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680341.aspx
        /// </remarks>
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

        /// <summary>
        /// Gets the preferred address of the first byte of the image when it is loaded in memory.
        /// </summary>
        public ulong ImageBase
        {
            get
            {
                return this.is32BitHeader ? this.OptionalHeader32.ImageBase : this.OptionalHeader64.ImageBase;
            }
        }

        /// <summary>
        /// Gets a pointer to the beginning of the code section, relative to the image base.
        /// </summary>
        public uint BaseOfCodeInMemory
        {
            get
            {
                return this.is32BitHeader ? this.OptionalHeader32.BaseOfCode : this.OptionalHeader64.BaseOfCode;
            }
        }

        /// <summary>
        /// Gets the size of the code section, in bytes, or the sum of all such sections if there are multiple code
        /// sections.
        /// </summary>
        public uint SizeOfCode
        {
            get
            {
                return this.is32BitHeader ? this.OptionalHeader32.SizeOfCode : this.OptionalHeader64.SizeOfCode;
            }
        }

        /// <summary>
        /// Gets a pointer to the offset of the beginning of the .text section in the PE file.
        /// </summary>
        public uint BaseOfCodeInFile
        {
            get
            {
                return this.sectionHeaders.FirstOrDefault(x => x.Section.StartsWith(".text")).PointerToRawData;
            }
        }

        /// <summary>
        /// Gets a collection of basic blocks in the PE file.
        /// </summary>
        public Dictionary<ulong, BasicBlock> BasicBlocks { get; private set; }

        public Dictionary<ulong, Disasm> Instructions { get; private set; }

        public Dictionary<ulong, Function> Functions { get; private set; }

        private bool AllBytesHaveBeenProcessed
        {
            get
            {
                return this.FirstUnprocessedVirtualAddress == null;
            }
        }

        private ulong? FirstUnprocessedVirtualAddress
        {
            get
            {
                // Scan for an unprocessed byte, starting at the last confirmed unprocessed code offset.
                for (ulong i = this.firstUnprocessedCodeOffset; i < (ulong)this.code.Length; ++i)
                {
                    if (this.byteTypes[i] == ByteType.Unprocessed ||
                        this.byteTypes[i] == ByteType.ExpectedInstructionStart)
                    {
                        // Return the first discovered unprocessed byte.
                        this.firstUnprocessedCodeOffset = i;
                        return this.GetVirtualAddressFromCodeOffset(this.firstUnprocessedCodeOffset);
                    }
                }

                // Return null if no unprocessed bytes exist.
                return null;
            }
        }

        private int AddressSize
        {
            get
            {
                return this.is32BitHeader ? 4 : 8;
            }
        }

        /// <summary>
        /// Gets the number of sections in the NT file header.
        /// </summary>
        private uint NumberOfSections
        {
            get
            {
                return this.is32BitHeader ?
                    this.ntHeaders32.FileHeader.NumberOfSections : this.ntHeaders64.FileHeader.NumberOfSections;
            }
        }

        /// <summary>
        /// Gets the optional file header from the NT file header. Check is32BitHeader to determine if this or
        /// OptionalHeader64 should be used.
        /// </summary>
        private IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return this.ntHeaders32.OptionalHeader;
            }
        }

        /// <summary>
        /// Gets the optional file header from the NT file header. Check is32BitHeader to determine if this or
        /// OptionalHeader32 should be used.
        /// </summary>
        private IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return this.ntHeaders64.OptionalHeader;
            }
        }

        #endregion Properties

        #region Methods

        public void IdentifyFunctions()
        {
            Dictionary<ulong, Function> functions = new Dictionary<ulong, Function>();

            // Get a collection of basic blocks that have no previous basic blocks.
            Dictionary<ulong, BasicBlock> startingBlocks = new Dictionary<ulong, BasicBlock>();
            foreach (BasicBlock bb in this.BasicBlocks.Values)
            {
                if (bb.PreviousBasicBlocks.Count == 0)
                {
                    startingBlocks[bb.FirstInstructionAddress] = bb;
                }
            }

            foreach (BasicBlock bb in startingBlocks.Values)
            {
                Dictionary<ulong, BasicBlock> connectedBlocks = PEFile.FindAllConnectedBasicBlocks(bb);
                Function f = new Function(bb.FirstInstructionAddress);
                foreach (BasicBlock connectedBlock in connectedBlocks.Values)
                {
                    f.BasicBlocks.Add(connectedBlock.FirstInstructionAddress, connectedBlock);
                }

                functions.Add(f.FirstInstructionAddress, f);
            }

            this.Functions = functions;
        }

        public void FindInstructionsAndBasicBlocks()
        {
            Dictionary<ulong, BeaEngineCS.BeaEngine._Disasm> instructions = new Dictionary<ulong, BeaEngineCS.BeaEngine._Disasm>();
            HashSet<ulong> remainingAddresses = new HashSet<ulong>();
            Dictionary<ulong, BasicBlock> basicBlocks = new Dictionary<ulong, BasicBlock>();
            bool isFirstPass = true;

            // Recursively scan this file for instructions and basic blocks.
            while (!this.AllBytesHaveBeenProcessed)
            {
                if (isFirstPass)
                {
                    isFirstPass = false;
                    ulong entryPoint = this.ImageBase + (this.is32BitHeader ?
                        this.OptionalHeader32.AddressOfEntryPoint : this.OptionalHeader64.AddressOfEntryPoint);
                    remainingAddresses.Add(entryPoint);
                }
                else
                {
                    remainingAddresses.Add((ulong)this.FirstUnprocessedVirtualAddress);
                }

                while (remainingAddresses.Count > 0)
                {
                    this.FindInstructions(instructions, remainingAddresses, basicBlocks);
                }
            }

            // Set the instructions for this PE file.
            this.Instructions = instructions;

            // Fill in the basic blocks with instructions.
            BasicBlock currentBasicBlock = null;
            foreach (Disasm i in this.Instructions.Values.OrderBy(x => x.VirtualAddr))
            {
                // See if a basic block starts at this instruction's address.
                if (basicBlocks.ContainsKey(i.VirtualAddr))
                {
                    // If so, move to that basic block.
                    currentBasicBlock = basicBlocks[i.VirtualAddr];
                }

                // Add the current instruction to the current basic block.
                currentBasicBlock.Instructions.Add(i);
            }

            // Check for empty basic blocks.
            if (basicBlocks.Values.Where(x => x.Instructions.Count == 0).Count() > 0)
            {
                throw new Exception("Some basic blocks have no instructions.");
            }

            // Look for basic blocks with a single nop instruction. If the basic block does not have a block
            // immediately following it, then remove the basic block with the nop instruction.
            ulong fallThroughAddress = ulong.MaxValue;
            foreach (BasicBlock bb in basicBlocks.Values.ToList())
            {
                // Find all basic blocks with a single instruction.
                if (bb.Instructions.Count == 1)
                {
                    // Narrow that down to only basic blocks with a single nop instruction.
                    Disasm instruction = bb.Instructions.First();
                    if (this.IsNopInstruction(instruction))
                    {
                        // Check to see if a fall-through instruction exists after this nop instruction.
                        fallThroughAddress = instruction.VirtualAddr + (ulong)instruction.Length;
                        if (!basicBlocks.ContainsKey(fallThroughAddress))
                        {
                            // If no fall-through instruction exists, remove this basic block and the nop instruction.
                            basicBlocks.Remove(instruction.VirtualAddr);
                            this.Instructions.Remove(instruction.VirtualAddr);
                        }
                    }
                }
            }

            // Remove the last basic block if it contains only nulls until the end of the code section.
            ulong lastBasicBlockAddress = basicBlocks.Last().Value.FirstInstructionAddress;
            ulong lastBasicBlockCodeOffset = this.GetCodeOffsetFromVirtualAddress(lastBasicBlockAddress);
            bool containsAllZeros = true;
            for (ulong i = lastBasicBlockCodeOffset; i < (ulong)this.code.Length; ++i)
            {
                containsAllZeros &= this.code[i] == 0x00;
            }
            if (containsAllZeros)
            {
                basicBlocks.Remove(basicBlocks.Last().Key);
            }

            // Link the basic blocks together.
            BasicBlock lastBasicBlock = basicBlocks.Last().Value;
            ulong lastValidInstructionAddress = basicBlocks.Last().Value.Instructions.Last().VirtualAddr;
            foreach (BasicBlock bb in basicBlocks.Values)
            {
                Disasm lastInstruction = bb.Instructions.Last();
                ulong branchTarget = lastInstruction.Instruction.AddrValue;
                fallThroughAddress = lastInstruction.VirtualAddr + (ulong)lastInstruction.Length;

                switch (lastInstruction.Instruction.BranchType)
                {
                    case BeaEngine.BranchType.None:
                    case BeaEngine.BranchType.CallType:
                        this.ConnectFallThroughBasicBlock(fallThroughAddress, bb, basicBlocks);
                        break;

                    case BeaEngine.BranchType.RetType:
                        break;

                    case BeaEngine.BranchType.JmpType:
                    default:
                        if (branchTarget == 0)
                        {
                            // Look for a jump table.
                            ulong jumpTableAddress = (ulong)lastInstruction.Argument1.Memory.Displacement;
                            HashSet<ulong> jumpTableEntries = this.GetJumpTableAddresses(jumpTableAddress);

                            // Link to each target basic block.
                            foreach (ulong address in jumpTableEntries)
                            {
                                if (!basicBlocks.ContainsKey(address))
                                {
                                    throw new Exception("No basic block exists for this jump table entry.");
                                }

                                // Link to the jump target block.
                                BasicBlock jumpTargetBlock = basicBlocks[address];
                                bb.NextBasicBlocks.Add(jumpTargetBlock);
                                jumpTargetBlock.PreviousBasicBlocks.Add(bb);
                            }

                            break;
                        }

                        // Link the branch target to this basic block.
                        if (!basicBlocks.ContainsKey(branchTarget))
                        {
                            throw new Exception("A basic block for the branch target is missing.");
                        }
                        else
                        {
                            // Create forward and backward links.
                            BasicBlock branchTargetBlock = basicBlocks[branchTarget];
                            bb.NextBasicBlocks.Add(branchTargetBlock);
                            branchTargetBlock.PreviousBasicBlocks.Add(bb);
                        }

                        // Mark the next basic block as a fall-through block if this is a conditional branch.
                        if (lastInstruction.Instruction.BranchType != BeaEngine.BranchType.JmpType)
                        {
                            this.ConnectFallThroughBasicBlock(fallThroughAddress, bb, basicBlocks);
                        }

                        break;
                }
            }

            // Set this PE file's collection of basic blocks.
            this.BasicBlocks = basicBlocks;
        }

        private void ConnectFallThroughBasicBlock(ulong fallThroughAddress, BasicBlock currentBlock, Dictionary<ulong, BasicBlock> basicBlocks)
        {
            Disasm lastInstruction = currentBlock.Instructions.Last();
            fallThroughAddress = lastInstruction.VirtualAddr + (ulong)lastInstruction.Length;

            if (!basicBlocks.ContainsKey(fallThroughAddress))
            {
                throw new Exception("A basic block for the fall through instruction is missing.");
            }

            BasicBlock fallThroughBlock = basicBlocks[fallThroughAddress];
            currentBlock.NextBasicBlocks.Add(fallThroughBlock);
            fallThroughBlock.PreviousBasicBlocks.Add(currentBlock);
        }

        private void FindInstructions(Dictionary<ulong, Disasm> instructions, HashSet<ulong> remainingAddresses, Dictionary<ulong, BasicBlock> basicBlocks)
        {
            // Create a new set of instructions if needed.
            if (instructions == null)
            {
                instructions = new Dictionary<ulong, Disasm>();
            }

            if (remainingAddresses == null)
            {
                remainingAddresses = new HashSet<ulong>();
            }

            if (basicBlocks == null)
            {
                basicBlocks = new Dictionary<ulong, BasicBlock>();
            }

            // Initialize the current virtual address.
            ulong currentVirtualAddress = 0;
            if (remainingAddresses.Count == 0)
            {
                currentVirtualAddress = this.BaseOfCodeInMemory + this.ImageBase;
            }
            else
            {
                currentVirtualAddress = remainingAddresses.First();
                remainingAddresses.Remove(currentVirtualAddress);
            }

            ulong baseCodeOffset = this.GetCodeOffsetFromVirtualAddress(currentVirtualAddress);

            // If this address has already been evaluated, then stop disassembling.
            if (instructions.ContainsKey(currentVirtualAddress))
            {
                // Make sure the byte is marked as the start of an instruction.
                this.byteTypes[baseCodeOffset] = ByteType.InstructionStart;

                // Make sure that a basic block exists for this instruction.
                if (!basicBlocks.ContainsKey(currentVirtualAddress))
                {
                    basicBlocks.Add(currentVirtualAddress, new BasicBlock(currentVirtualAddress));
                }

                return;
            }

            // If this is not a valid address, then stop disassembling.
            if (!this.IsValidVirtualAddress(currentVirtualAddress))
            {
                return;
            }

            // If this byte is an alignment byte, then mark it as such and stop disassembling.
            if (this.alignmentBytes.Contains(this.code[baseCodeOffset]))
            {
                this.byteTypes[baseCodeOffset] = ByteType.AlignmentByte;
                return;
            }

            // If a multi-byte nop exists at this instruction, mark it and stop disassembling.
            ulong? numNopBytesAtCodeOffset = this.GetNumNopBytesAtCodeOffset(baseCodeOffset);
            if (numNopBytesAtCodeOffset != null)
            {
                this.byteTypes[baseCodeOffset] = ByteType.MultiByteNopStart;
                for (ulong i = 1; i < (ulong)numNopBytesAtCodeOffset; ++i)
                {
                    this.byteTypes[baseCodeOffset + i] = ByteType.MultiByteNopPart;
                }

                // Add the nop instruction to the list of instructions.
                Disasm nopInstruction = this.DisassembleInstruction(currentVirtualAddress);
                instructions.Add(nopInstruction.VirtualAddr, nopInstruction);

                // Create a basic block for the nop instruction.
                PEFile.AddBasicBlock(nopInstruction.VirtualAddr, basicBlocks);

                // Stop disassembling.
                return;
            }

            // If this is a jump table, mark it as such, add the referenced addresses to the collection for analysis,
            // and return.
            if (this.byteTypes[baseCodeOffset] == ByteType.Unprocessed)
            {
                HashSet<ulong> jumpTableAddresses =
                    this.GetJumpTableAddresses(this.GetVirtualAddressFromCodeOffset(baseCodeOffset));
                if (jumpTableAddresses.Count > 1)
                {
                    int addressSize = this.AddressSize;

                    // Mark the bytes as an entry in a jump table.
                    for (int i = 0; i < jumpTableAddresses.Count; ++i)
                    {
                        ulong addressOffset = (ulong)(i * addressSize) + baseCodeOffset;
                        this.byteTypes[addressOffset] = ByteType.JumpTableAddressStart;
                        for (int addressByte = 1; addressByte < addressSize; ++addressByte)
                        {
                            this.byteTypes[addressOffset + (ulong)addressByte] = ByteType.JumpTableAddressPart;
                        }
                    }

                    foreach (ulong address in jumpTableAddresses)
                    {
                        remainingAddresses.Add(address);
                    }

                    return;
                }
            }

            // Initialize the disassembler variables.
            BeaEngine.Architecture arch
                = this.is32BitHeader ? BeaEngine.Architecture.x86_32 : BeaEngine.Architecture.x86_64;

            bool stopEvaluation = false;

            // Create a new basic block based on the current virtual address.
            PEFile.AddBasicBlock(currentVirtualAddress, basicBlocks);

            foreach (Disasm i in BeaEngine.Disassemble(this.code, currentVirtualAddress, arch, this.GetCodeOffsetFromVirtualAddress(currentVirtualAddress)))
            {
                // If this address has already been evaluated, then stop disassembling.
                if (instructions.ContainsKey(i.VirtualAddr))
                {
                    return;
                }

                // Add the instruction.
                instructions.Add(i.VirtualAddr, i);

                // Mark the first byte as the start of an instruction.
                ulong codeOffset = this.GetCodeOffsetFromVirtualAddress(i.VirtualAddr);
                this.byteTypes[codeOffset] = ByteType.InstructionStart;

                // Mark each subsequent byte of the instruction as part of an instruction.
                for (ulong j = 1; j < (ulong)i.Length; ++j)
                {
                    this.byteTypes[codeOffset + j] = ByteType.InstructionPart;
                }

                switch (i.Instruction.BranchType)
                {
                    case BeaEngine.BranchType.RetType:
                        stopEvaluation = true;
                        break;
                    case BeaEngine.BranchType.JmpType:
                        // Move to the target instruction, since no follow through instruction will be hit from this
                        // instruction.
                        if (i.Instruction.AddrValue != 0)
                        {
                            remainingAddresses.Add(i.Instruction.AddrValue);

                            // Mark the branch target as an expected instruction.
                            this.MarkVirtualAddressAsExpectedInstruction(i.Instruction.AddrValue);
                        }
                        else
                        {
                            if (i.Argument1.Memory.Displacement != 0)
                            {
                                ulong jumpTableAddress = (ulong)i.Argument1.Memory.Displacement;
                                HashSet<ulong> jumpTableAddresses = this.GetJumpTableAddresses(jumpTableAddress);
                                foreach (ulong address in jumpTableAddresses)
                                {
                                    remainingAddresses.Add(address);

                                    // Mark the jump target as an expected instruction.
                                    this.MarkVirtualAddressAsExpectedInstruction(address);
                                }
                            }
                        }

                        stopEvaluation = true;
                        break;
                    case BeaEngine.BranchType.CallType:
                        // Add the called function to the set of addresses to disassemble.
                        if (i.Instruction.AddrValue != 0)
                        {
                            remainingAddresses.Add(i.Instruction.AddrValue);

                            // Mark the branch target as an expected instruction.
                            this.MarkVirtualAddressAsExpectedInstruction(i.Instruction.AddrValue);
                        }

                        break;
                    default:
                        // Add the conditional branch target and fall through instruction to the set of addresses to
                        // disassemble.
                        if (i.Instruction.AddrValue != 0)
                        {
                            ulong fallThroughInstructionAddress = i.VirtualAddr + (ulong)i.Length;

                            remainingAddresses.Add(i.Instruction.AddrValue);
                            remainingAddresses.Add(fallThroughInstructionAddress);

                            // Mark the branch target and fall through instruction as expected instructions.
                            this.MarkVirtualAddressAsExpectedInstruction(i.Instruction.AddrValue);
                            this.MarkVirtualAddressAsExpectedInstruction(fallThroughInstructionAddress);
                        }

                        break;
                }

                // See if this instruction references memory at a displaced address.
                if (i.Instruction.Mnemonic.StartsWith("movzx") &&
                    this.IsValidVirtualAddress((ulong)i.Argument2.Memory.Displacement))
                {
                    ulong dataOffset = this.GetCodeOffsetFromVirtualAddress((ulong)i.Argument2.Memory.Displacement);

                    // Mark the byte as the beginning of data.
                    this.byteTypes[dataOffset] = ByteType.ArbitraryDataStart;

                    // Scan until either a single alignment byte or multi-byte nop is hit.
                    while (++dataOffset < (ulong)this.code.Length)
                    {
                        // If the next byte is an alignment byte or the next two bytes are a multy-byte nop, add the
                        // code offset to the set of addresses to analyze.
                        if (this.alignmentBytes.Contains(this.code[dataOffset]) ||
                            this.GetNumNopBytesAtCodeOffset(dataOffset) != null)
                        {
                            remainingAddresses.Add(this.GetVirtualAddressFromCodeOffset(dataOffset));
                            return;
                        }

                        this.byteTypes[dataOffset] = ByteType.ArbitraryDataPart;
                    }
                }

                if (stopEvaluation)
                {
                    break;
                }
            }
        }

        private static void AddBasicBlock(ulong virtualAddress, Dictionary<ulong, BasicBlock> basicBlocks)
        {
            if (!basicBlocks.ContainsKey(virtualAddress))
            {
                basicBlocks.Add(virtualAddress, new BasicBlock(virtualAddress));
            }
        }

        private Disasm DisassembleInstruction(ulong virtualAddress)
        {
            ulong codeOffset = this.GetCodeOffsetFromVirtualAddress(virtualAddress);
            BeaEngine.Architecture arch
                = this.is32BitHeader ? BeaEngine.Architecture.x86_32 : BeaEngine.Architecture.x86_64;
            return BeaEngine.Disassemble(this.code, virtualAddress, arch, codeOffset).First();
        }

        private static Dictionary<ulong, BasicBlock> FindAllConnectedBasicBlocks(BasicBlock bb)
        {
            // Look for connected blocks.
            Dictionary<ulong, BasicBlock> connectedBlocks = new Dictionary<ulong, BasicBlock>();
            Dictionary<ulong, BasicBlock> addedBlocks = new Dictionary<ulong, BasicBlock>();
            addedBlocks.Add(bb.FirstInstructionAddress, bb);
            while (addedBlocks.Count > 0)
            {
                // Add the newly discovered connected basic blocks.
                foreach (BasicBlock addedBlock in addedBlocks.Values)
                {
                    connectedBlocks.Add(addedBlock.FirstInstructionAddress, addedBlock);
                }

                // Clear the set of newly discovered connected basic blocks.
                addedBlocks = new Dictionary<ulong, BasicBlock>();

                // Iterate over the current set of connected blocks, looking for more connected blocks.
                foreach (BasicBlock connectedBlock in connectedBlocks.Values)
                {
                    foreach (BasicBlock nextBlock in connectedBlock.NextBasicBlocks)
                    {
                        if (!connectedBlocks.ContainsKey(nextBlock.FirstInstructionAddress) &&
                            !addedBlocks.ContainsKey(nextBlock.FirstInstructionAddress))
                        {
                            addedBlocks.Add(nextBlock.FirstInstructionAddress, nextBlock);
                        }
                    }

                    foreach (BasicBlock previousBlock in connectedBlock.PreviousBasicBlocks)
                    {
                        if (!connectedBlocks.ContainsKey(previousBlock.FirstInstructionAddress) &&
                            !addedBlocks.ContainsKey(previousBlock.FirstInstructionAddress))
                        {
                            addedBlocks.Add(previousBlock.FirstInstructionAddress, previousBlock);
                        }
                    }
                }
            }

            return connectedBlocks;
        }

        private void MarkVirtualAddressAsExpectedInstruction(ulong virtualAddress)
        {
            ulong codeOffset = this.GetCodeOffsetFromVirtualAddress(virtualAddress);
            ByteType bt = this.byteTypes[codeOffset];
            if (this.byteTypes[codeOffset] == ByteType.Unprocessed)
            {
                this.byteTypes[codeOffset] = ByteType.ExpectedInstructionStart;
            }
            else if (this.byteTypes[codeOffset] == ByteType.ExpectedInstructionStart ||
                this.byteTypes[codeOffset] == ByteType.InstructionStart)
            {
                // Ignore these cases.
            }
            else if (this.byteTypes[codeOffset] == ByteType.ArbitraryDataStart ||
                this.byteTypes[codeOffset] == ByteType.ArbitraryDataPart)
            {
                this.byteTypes[codeOffset] = ByteType.ExpectedInstructionStart;
            }
            else
            {
                Console.WriteLine();
            }
        }

        /// <remarks>
        /// Documented nop instructions:
        /// nop               // nop
        /// xchg eax, eax     // http://stackoverflow.com/a/2703440/770370 // interpreted as 'nop' in BeaEngine
        /// mov eax, eax      // http://stackoverflow.com/a/2703440/770370
        /// lea eax, [eax+00] // http://stackoverflow.com/a/2703440/770370
        /// lea ebx, [ebx+00] // http://www.strchr.com/machine_code_redundancy
        /// lea esp, [esp+00] // http://www.strchr.com/machine_code_redundancy
        /// </remarks>
        private bool IsNopInstruction(Disasm instruction)
        {
            if (instruction.Instruction.Opcode == 0x90)
            {
                return true;
            }

            // Check for: mov XYZ, XYZ
            if (instruction.Instruction.InstructionType == BeaEngine.InstructionType.DATA_TRANSFER &&
                instruction.Argument1.AccessMode == BeaEngine.AccessMode.WRITE &&
                instruction.Argument2.AccessMode == BeaEngine.AccessMode.READ &&
                instruction.Argument1.Details == (BeaEngine.ArgumentDetails.REGISTER_TYPE | BeaEngine.ArgumentDetails.GENERAL_REG) &&
                instruction.Argument2.Details == (BeaEngine.ArgumentDetails.REGISTER_TYPE | BeaEngine.ArgumentDetails.GENERAL_REG) &&
                instruction.Argument1.ArgMnemonic.Equals(instruction.Argument2.ArgMnemonic))
            {
                return true;
            }

            // Check for: lea XYZ, [XYZ+00h]
            if (instruction.Argument1.AccessMode == BeaEngine.AccessMode.WRITE &&
                instruction.Argument2.AccessMode == BeaEngine.AccessMode.None &&
                instruction.Argument1.RegisterId == (BeaEngine.RegisterId)instruction.Argument2.Memory.BaseRegister &&
                instruction.Argument2.Memory.IndexRegister == 0 &&
                instruction.Argument2.Memory.Displacement == 0)
            {
                return true;
            }

            return false;
        }

        private ulong? GetNumNopBytesAtCodeOffset(ulong codeOffset)
        {
            // Calculate the virtual address.
            ulong virtualAddress = this.GetVirtualAddressFromCodeOffset(codeOffset);

            // Disassemble the instruction at this address.
            BeaEngine.Architecture arch
                = this.is32BitHeader ? BeaEngine.Architecture.x86_32 : BeaEngine.Architecture.x86_64;
            Disasm instruction = BeaEngine.Disassemble(this.code, virtualAddress, arch, codeOffset).First();

            if (this.IsNopInstruction(instruction))
            {
                return (ulong)instruction.Length;
            }

            return null;
        }

        private ulong GetVirtualAddressFromCodeOffset(ulong codeOffset)
        {
            return codeOffset + this.BaseOfCodeInMemory + this.ImageBase;
        }

        private ulong GetCodeOffsetFromVirtualAddress(ulong virtualAddress)
        {
            return virtualAddress - this.BaseOfCodeInMemory - this.ImageBase;
        }

        private bool IsValidVirtualAddress(ulong virtualAddress)
        {
            int addressSize = this.is32BitHeader ? 4 : 8;
            ulong firstPossibleAddress = this.ImageBase + this.BaseOfCodeInMemory;
            ulong lastPossibleAddress = firstPossibleAddress + (ulong)this.code.Length - (ulong)addressSize;
            return firstPossibleAddress <= virtualAddress && virtualAddress <= lastPossibleAddress;
        }

        /// <summary>
        /// Scans data for references to addresses in the code section.
        /// </summary>
        /// <param name="dataVirtualBaseAddress">the virtual address of the data being scanned</param>
        /// <returns>a collection of discovered jump table offsets</returns>
        private HashSet<ulong> GetJumpTableAddresses(ulong virtualAddress, bool isRecursiveCall = false)
        {
            // If this is not a valid virtual address, return an empty jump table address list.
            if (!this.IsValidVirtualAddress(virtualAddress))
            {
                return new HashSet<ulong>();
            }

            int addressSize = this.AddressSize;
            ulong codeOffset = this.GetCodeOffsetFromVirtualAddress(virtualAddress);

            ByteType bt = this.byteTypes[codeOffset];

            // This has been marked as the start of an instruction, so return an empty jump table address list.
            if (this.byteTypes[codeOffset] == ByteType.InstructionStart ||
                this.byteTypes[codeOffset] == ByteType.ExpectedInstructionStart)
            {
                return new HashSet<ulong>();
            }

            if (this.byteTypes[codeOffset] == ByteType.InstructionPart)
            {
                if (isRecursiveCall)
                {
                    // Do not do multiple recursive calls. Simply abort.
                    return new HashSet<ulong>();
                }
                else
                {
                    return this.GetJumpTableAddresses(virtualAddress + (ulong)addressSize, true);
                }
            }

            if (this.byteTypes[codeOffset] != ByteType.Unprocessed &&
                this.byteTypes[codeOffset] != ByteType.JumpTableAddressStart &&
                this.byteTypes[codeOffset] != ByteType.ArbitraryDataStart &&
                this.byteTypes[codeOffset] != ByteType.ArbitraryDataPart)
            {
                Console.WriteLine();
            }

            byte[] addressBytes = new byte[addressSize];
            ulong firstPossibleAddress = this.ImageBase + this.BaseOfCodeInMemory;
            ulong lastPossibleAddress = firstPossibleAddress + (ulong)this.code.Length - (ulong)addressSize;
            HashSet<ulong> jumpTableOffsets = new HashSet<ulong>();

            for (ulong i = codeOffset; i < (ulong)this.code.Length - (ulong)addressSize; ++i)
            {
                // Copy a byte array to see if it is an address.
                Array.Copy(this.code, (long)i, addressBytes, 0, addressSize);

                // Convert the byte array to an address.
                ulong jumpTableEntry = this.is32BitHeader ? BitConverter.ToUInt32(addressBytes, 0) : BitConverter.ToUInt64(addressBytes, 0);

                // Check to see if the jump table address exists within the code address range.
                if (this.IsValidVirtualAddress(jumpTableEntry))
                {
                    // Add the jump table address.
                    jumpTableOffsets.Add(jumpTableEntry);

                    // Mark these bytes as jump table offsets.
                    ByteType bt1 = this.byteTypes[i];
                    if (this.byteTypes[i] != ByteType.Unprocessed &&
                        this.byteTypes[i] != ByteType.JumpTableAddressStart &&
                        this.byteTypes[i] != ByteType.ArbitraryDataStart &&
                        this.byteTypes[i] != ByteType.ArbitraryDataPart)
                    {
                        Console.WriteLine();
                    }
                    this.byteTypes[i] = ByteType.JumpTableAddressStart;
                    for (int j = 1; j < addressSize; ++j)
                    {
                        this.byteTypes[i + (ulong)j] = ByteType.JumpTableAddressPart;
                    }

                    // Increment the index by the address size - 1.
                    i += (ulong)addressSize - 1;
                }
                else
                {
                    break;
                }
            }

            return jumpTableOffsets;
        }

        /// <summary>
        /// Reads in a block from a binary stream and converts it to the struct type specified by the template
        /// parameter.
        /// </summary>
        /// <typeparam name="T">the type of structure being read</typeparam>
        /// <param name="reader">a binary reader that places the data into a struct of type T</param>
        /// <returns>a new object composed of bytes read by the reader into the supplied type of object</returns>
        private static T ReadToStruct<T>(BinaryReader reader)
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

        #region Structures

        [SuppressMessage("Microsoft.StyleCop.CSharp.NamingRules", "SA1307:AccessibleFieldsMustBeginWithUpperCaseLetter", Justification = "Using Microsoft structure field names.")]
        [SuppressMessage("Microsoft.StyleCop.CSharp.NamingRules", "SA1310:FieldNamesMustNotContainUnderscore", Justification = "Using Microsoft structure field names.")]
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1630:DocumentationTextMustContainWhitespace", Justification = "Using Microsoft comments.")]
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            /// <summary>
            /// Magic number
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;

            /// <summary>
            /// Bytes on last page of file
            /// </summary>
            public ushort e_cblp;

            /// <summary>
            /// Pages in file
            /// </summary>
            public ushort e_cp;

            /// <summary>
            /// Relocations
            /// </summary>
            public ushort e_crlc;

            /// <summary>
            /// Size of header in paragraphs
            /// </summary>
            public ushort e_cparhdr;

            /// <summary>
            /// Minimum extra paragraphs needed
            /// </summary>
            public ushort e_minalloc;

            /// <summary>
            /// Maximum extra paragraphs needed
            /// </summary>
            public ushort e_maxalloc;

            /// <summary>
            /// Initial (relative) SS value
            /// </summary>
            public ushort e_ss;

            /// <summary>
            /// Initial SP value
            /// </summary>
            public ushort e_sp;

            /// <summary>
            /// Checksum
            /// </summary>
            public ushort e_csum;

            /// <summary>
            /// Initial IP value
            /// </summary>
            public ushort e_ip;

            /// <summary>
            /// Initial (relative) CS value
            /// </summary>
            public ushort e_cs;

            /// <summary>
            /// File address of relocation table
            /// </summary>
            public ushort e_lfarlc;

            /// <summary>
            /// Overlay number
            /// </summary>
            public ushort e_ovno;

            /// <summary>
            /// Reserved words
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;

            /// <summary>
            /// OEM identifier (for e_oeminfo)
            /// </summary>
            public ushort e_oemid;

            /// <summary>
            /// OEM information; e_oemid specific
            /// </summary>
            public ushort e_oeminfo;

            /// <summary>
            /// Reserved words
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;

            /// <summary>
            /// File address of new exe header
            /// </summary>
            public int e_lfanew;
        }

        /// <summary>
        /// Represents the PE header format. (32-bit version)
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
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

        /// <summary>
        /// Represents the PE header format. (64-bit version)
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
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

        /// <summary>
        /// Represents the COFF header format.
        /// </summary>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public MachineType Machine;

            public ushort NumberOfSections;

            public uint TimeDateStamp;

            public uint PointerToSymbolTable;

            public uint NumberOfSymbols;

            public ushort SizeOfOptionalHeader;

            public IFHCharacteristics Characteristics;
        }

        /// <summary>
        /// Represents the optional header format. (32-bit version)
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
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

        /// <summary>
        /// Represents the optional header format. (64-bit version)
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Using Microsoft structures.")]
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

        /// <summary>
        /// Represents the data directory.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680305.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Documented online at MSDN.")]
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;

            public uint Size;
        }

        /// <summary>
        /// Represents the image section header format.
        /// </summary>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/ms680341.aspx
        /// </remarks>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Documented online at MSDN.")]
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public uint VirtualSize;

            [FieldOffset(12)]
            public uint VirtualAddress;

            [FieldOffset(16)]
            public uint SizeOfRawData;

            [FieldOffset(20)]
            public uint PointerToRawData;

            [FieldOffset(24)]
            public uint PointerToRelocations;

            [FieldOffset(28)]
            public uint PointerToLinenumbers;

            [FieldOffset(32)]
            public ushort NumberOfRelocations;

            [FieldOffset(34)]
            public ushort NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            /// <summary>
            /// Gets a string representation of the section.
            /// </summary>
            public string Section
            {
                get { return new string(this.Name); }
            }
        }

        #endregion

        #region Classes
        /*
        /// <summary>
        /// Represents a chunk of data in the PE file.
        /// </summary>
        public class DataChunk : CodeChunk
        {
            /// <summary>
            /// Initializes a new instance of the DataChunk class.
            /// </summary>
            /// <param name="cc">a CodeChunk from which this DataChunk is derived</param>
            public DataChunk(CodeChunk cc)
            {
                this.Offset = cc.Offset;
                this.Code = cc.Code;
                this.EndsOnAlignmentBoundary = cc.EndsOnAlignmentBoundary;
            }

            /// <summary>
            /// Initializes a new instance of the DataChunk class.
            /// </summary>
            /// <param name="offset">the offset from the base of the code segment</param>
            /// <param name="length">the number of bytes in this data chunk</param>
            /// <param name="endsOnAlignmentBoundary">
            /// true if the data chunk stops adjacent to a byte alignment boundary
            /// </param>
            public DataChunk(ulong offset, ulong length, bool endsOnAlignmentBoundary)
            {
                this.Offset = offset;
                this.Code = new byte[length];
                this.EndsOnAlignmentBoundary = endsOnAlignmentBoundary;
            }
        }

        /// <summary>
        /// Represents an array of bytes of code stored at an offset from the base of the code segment.
        /// </summary>
        public class CodeChunk
        {
            /// <summary>
            /// Initializes a new instance of the CodeChunk class.
            /// </summary>
            public CodeChunk()
            {
                this.Offset = ulong.MaxValue;
                this.Code = new byte[0];
                this.EndsOnAlignmentBoundary = false;
            }

            /// <summary>
            /// Initializes a new instance of the CodeChunk class.
            /// </summary>
            /// <param name="offset">the offset from the base of the code segment</param>
            /// <param name="length">the number of bytes in this code chunk</param>
            /// <param name="endsOnAlignmentBoundary">
            /// true if the code chunk stops adjacent to a byte alignment boundary
            /// </param>
            public CodeChunk(ulong offset, ulong length, bool endsOnAlignmentBoundary)
            {
                this.Offset = offset;
                this.Code = new byte[length];
                this.EndsOnAlignmentBoundary = endsOnAlignmentBoundary;
            }

            /// <summary>
            /// Gets or sets the offset from the base of the code segment.
            /// </summary>
            public ulong Offset { get; protected set; }

            /// <summary>
            /// Gets or sets the array of bytes in this code chunk.
            /// </summary>
            public byte[] Code { get; protected set; }

            /// <summary>
            /// Gets or sets a value indicating whether this code chunk stops adjacent to a byte alignment boundary.
            /// </summary>
            public bool EndsOnAlignmentBoundary { get; protected set; }
        }

        /// <summary>
        /// Represents a sequence of bytes that resides directly before and up to an alignment boundary.
        /// </summary>
        private class AlignmentByteSequence
        {
            /// <summary>
            /// Initializes a new instance of the AlignmentByteSequence class.
            /// </summary>
            /// <param name="offset">the sequence's offset from the base of the code segment</param>
            /// <param name="length">the number of bytes in the byte sequence</param>
            public AlignmentByteSequence(ulong offset, ulong length)
            {
                this.Offset = offset;
                this.Length = length;
            }

            /// <summary>
            /// Gets the sequence's offset from the base of the code segment.
            /// </summary>
            public ulong Offset { get; private set; }

            /// <summary>
            /// Gets the number of bytes in the byte sequence.
            /// </summary>
            public ulong Length { get; private set; }

            /// <summary>
            /// Gets the offset (from the base of the code segment) of the instruction that follows the byte sequence.
            /// </summary>
            public ulong NextInstructionOffset
            {
                get
                {
                    return this.Offset + this.Length;
                }
            }
        }

        /// <summary>
        /// Represents a memory address that is referenced from data in the PE file.
        /// </summary>
        private class DiscoveredReference
        {
            /// <summary>
            /// Initializes a new instance of the DiscoveredReference class.
            /// </summary>
            /// <param name="address">the virtual address at which the reference resides</param>
            /// <param name="addressSize">the number of bytes of the address that is referenced</param>
            public DiscoveredReference(ulong address, byte[] referencedAddressBytes)
            {
                this.Address = address;

                if (referencedAddressBytes.Length == 4)
                {
                    this.ReferencedAddress = BitConverter.ToUInt32(referencedAddressBytes, 0);
                }
                else
                {
                    this.ReferencedAddress += BitConverter.ToUInt64(referencedAddressBytes, 0);
                }
            }

            public DiscoveredReference(ulong address, ulong referencedAddress)
            {
                this.Address = address;
                this.ReferencedAddress = referencedAddress;
            }

            /// <summary>
            /// Gets the address at which the reference resides.
            /// </summary>
            public ulong Address { get; private set; }

            /// <summary>
            /// Gets the address that is referenced.
            /// </summary>
            public ulong ReferencedAddress { get; private set; }
        }
        */
        #endregion
    }
}
