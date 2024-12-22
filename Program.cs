using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CVE_SilentElevation
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            foreach (string exeFile in TryGetExes("C:\\"))
            {
                if (CanSilentElevate(exeFile))
                {
                    Console.WriteLine(exeFile);
                }
            }
            Console.WriteLine("DONE");
            Console.ReadLine();
        }
        private static void GetExesInternal(string folderPath, List<string> exes)
        {
            try
            {
                exes.AddRange(Directory.GetFiles(folderPath, "*.exe", SearchOption.TopDirectoryOnly));
            }
            catch { }
            try
            {
                foreach (string subFolderPath in Directory.GetDirectories(folderPath))
                {
                    GetExesInternal(subFolderPath, exes);
                }
            }
            catch { }
        }
        public static string[] TryGetExes(string folderPath)
        {
            List<string> output = new List<string>();

            GetExesInternal(folderPath, output);

            return output.ToArray();
        }
        public static bool CanSilentElevate(string exePath)
        {
            try
            {
                X509Certificate2 certificate = new X509Certificate2(exePath);
                if (certificate.Verify() && certificate.SerialNumber == "3300000460CF42A912315F6FB3000000000460")
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
