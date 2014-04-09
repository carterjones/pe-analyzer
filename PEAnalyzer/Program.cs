namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using Bunseki;

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
            PEFile pef = new PEFile(filename);
            pef.FindBasicBlocks2();
            pef.FindBasicBlocks();
            pef.CreateFunctions();

            Console.ReadKey(true);
        }
    }
}
