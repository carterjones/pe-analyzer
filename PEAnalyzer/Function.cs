namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    using Disasm = BeaEngineCS.BeaEngine._Disasm;

    public class Function
    {
        #region Fields

        readonly ulong firstInstructionAddress;

        readonly int hashCode;

        #endregion

        #region Constructors

        public Function(ulong firstInstructionAddress)
        {
            this.firstInstructionAddress = firstInstructionAddress;
            this.hashCode = this.FirstInstructionAddress.GetHashCode();
            this.BasicBlocks = new Dictionary<ulong, BasicBlock>();
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets a set of instructions that call this function.
        /// </summary>
        public HashSet<Disasm> CalledBy
        {
            get
            {
                if (this.BasicBlocks.Count > 0)
                {
                    return this.BasicBlocks[this.firstInstructionAddress].CalledBy;
                }
                else
                {
                    return new HashSet<Disasm>();
                }
            }
        }

        /// <summary>
        /// Gets a collection of basic blocks that make up this function.
        /// </summary>
        public Dictionary<ulong, BasicBlock> BasicBlocks { get; private set; }

        /// <summary>
        /// Gets or sets the address of the first instruction of this function.
        /// </summary>
        public ulong FirstInstructionAddress
        {
            get
            {
                return this.firstInstructionAddress;
            }
        }

        /// <summary>
        /// Gets the list of instructions within this function.
        /// </summary>
        public List<Disasm> Instructions
        {
            get
            {
                List<Disasm> instructions = new List<Disasm>();
                foreach (BasicBlock bb in this.BasicBlocks.Values)
                {
                    foreach (Disasm i in bb.Instructions)
                    {
                        instructions.Add(i);
                    }
                }

                return instructions;
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Returns a pre-computed hash code that uniquely identifies this function.
        /// </summary>
        /// <returns>a hash code that uniquely identifies this function</returns>
        public override int GetHashCode()
        {
            return this.hashCode;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current Function object.
        /// </summary>
        /// <param name="obj">The object to compare with the current Function object.</param>
        /// <returns>true if the specified object is equal to the current object; otherwise, false</returns>
        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != this.GetType())
            {
                return false;
            }

            Function bb = (Function)obj;
            return bb.FirstInstructionAddress == this.FirstInstructionAddress;
        }

        #endregion
    }
}
