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
            pef.FindInstructionsAndBasicBlocks();
            pef.IdentifyFunctions();

            Console.ReadKey(true);
        }
    }
}
