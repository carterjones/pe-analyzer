namespace PEAnalyzer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.IO;
    //using Capstone;
    using Bunseki;

    class Program
    {
        static void Main(string[] args)
        {
            string filename = @"D:\inbox\notepad++.exe";
            PEFile pef = new PEFile(filename);

            Console.ReadKey(true);
        }
    }
}
