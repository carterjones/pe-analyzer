﻿namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using BeaEngineCS;

    using Disasm = BeaEngineCS.BeaEngine._Disasm;

    /// <summary>
    /// Represents a basic block of instructions, containing at most one branching instruction at the end of the block.
    /// </summary>
    public class BasicBlock
    {
        #region Fields

        readonly ulong firstInstructionAddress;

        readonly int hashCode;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the BasicBlock class.
        /// </summary>
        public BasicBlock(ulong firstInstructionAddress)
        {
            this.firstInstructionAddress = firstInstructionAddress;
            this.hashCode = this.FirstInstructionAddress.GetHashCode();
            this.PreviousBasicBlocks = new HashSet<BasicBlock>();
            this.NextBasicBlocks = new HashSet<BasicBlock>();
            this.Instructions = new List<Disasm>();
            this.CalledBy = new HashSet<Disasm>();
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets links to basic blocks that precede this basic block.
        /// </summary>
        public HashSet<BasicBlock> PreviousBasicBlocks { get; private set; }

        /// <summary>
        /// Gets links to basic blocks that can be reached directly from this basic block.
        /// </summary>
        public HashSet<BasicBlock> NextBasicBlocks { get; private set; }

        /// <summary>
        /// Gets a set of instructions that call this basic block.
        /// </summary>
        public HashSet<Disasm> CalledBy { get; private set; }

        /// <summary>
        /// Gets or sets the address of the first instruction of this basic block.
        /// </summary>
        public ulong FirstInstructionAddress
        {
            get
            {
                return this.firstInstructionAddress;
            }
        }

        /// <summary>
        /// Gets the list of instructions within this basic block.
        /// </summary>
        public List<Disasm> Instructions { get; private set; }

        #endregion

        #region Methods

        /// <summary>
        /// Returns a pre-computed hash code that uniquely identifies this basic block.
        /// </summary>
        /// <returns>a hash code that uniquely identifies this basic block</returns>
        public override int GetHashCode()
        {
            return this.hashCode;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current BasicBlock object.
        /// </summary>
        /// <param name="obj">The object to compare with the current BasicBlock object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false</returns>
        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != this.GetType())
            {
                return false;
            }

            BasicBlock bb = (BasicBlock)obj;
            return bb.FirstInstructionAddress == this.FirstInstructionAddress;
        }

        #endregion
    }
}
