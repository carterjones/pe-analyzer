namespace Bunseki
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    public class BasicBlock
    {
        public UIntPtr FirstInstructionAddress { get; set; }

        public override int GetHashCode()
        {
            return this.FirstInstructionAddress.ToUInt64().GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != this.GetType())
            {
                return false;
            }

            BasicBlock bb = (BasicBlock)obj;
            return bb.FirstInstructionAddress.ToUInt64() == this.FirstInstructionAddress.ToUInt64();
        }
    }
}
