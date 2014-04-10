namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// The main class to be run when the executable is run.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// The entry function of the executable.
        /// </summary>
        /// <param name="args">arguments passed to the command line</param>
        public static void Main(string[] args)
        {
            string filename = @"D:\inbox\notepad++.exe";
            //string filename = @"D:\inbox\MRT.exe";
            PEFile pef = new PEFile(filename);
            Dictionary<ulong, BeaEngineCS.BeaEngine._Disasm> instructions = new Dictionary<ulong, BeaEngineCS.BeaEngine._Disasm>();
            HashSet<ulong> remainingAddresses = new HashSet<ulong>();
            Dictionary<ulong, BasicBlock> basicBlocks = new Dictionary<ulong, BasicBlock>();

            while (!pef.AllBytesHaveBeenProcessed)
            {
                remainingAddresses.Add((ulong)pef.FirstUnprocessedVirtualAddress);

                while (remainingAddresses.Count > 0)
                {
                    pef.FindInstructions(instructions, remainingAddresses, basicBlocks);
                }
            }

            Console.ReadKey(true);
        }
    }
}
