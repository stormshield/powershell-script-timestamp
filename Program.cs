using System;
using System.Collections.Generic;
using System.Linq;

namespace PowershellScriptTimestamp
{
    internal class Program
    {
        private const string ARG_POWERSHELL = "/powershell";
        private const string ARG_VBSCRIPT = "/vbscript";

        private const string ARG_SIGNTOOL_PATH = "/signtool";

        private const string ARG_SERVER_URI = "/tr";
        private const string ARG_DIGESTMETHOD = "/td";

        private static string[] ARGS_HELP = new string[] { "/?", "-h", "--help", "/h", "/help" };

        private static void Usage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine($"\t{AppDomain.CurrentDomain.FriendlyName} <file type> [<signtool spec>] <server spec> [<digest spec>] <file [...]>");
            Console.WriteLine("");
            Console.WriteLine($"\t\tfile type    : <{ARG_POWERSHELL} | {ARG_VBSCRIPT}>");
            Console.WriteLine($"\t\tsigntool spec: {ARG_SIGNTOOL_PATH} <signtool_path>");
            Console.WriteLine($"\t\tserver spec  : {ARG_SERVER_URI} <uri>");
            Console.WriteLine($"\t\tdigest spec  : {ARG_DIGESTMETHOD} <method>");
        }

        static int Main(string[] args)
        {
            TextFileTimestamp timestampObject = null;
            List<string> fileList = new List<string>();
            List<string> successfulList = new List<string>();
            List<string> failedList = new List<string>();

            string timestampServerUri = null;
            string digestAlgorithm = "sha256";
            string signToolPath = "signtool.exe";

            int argIndex = 0;
            while (argIndex < args.Length)
            {
                if (ARGS_HELP.Any(spec => args[argIndex].Equals(spec, StringComparison.OrdinalIgnoreCase)))
                {
                    Usage();
                    return -1;
                }
                else if (args[argIndex].Equals(ARG_POWERSHELL, StringComparison.OrdinalIgnoreCase))
                {
                    timestampObject = new TextFileTimestamp(traits: new PowershellSignatureTraits());
                }
                else if (args[argIndex].Equals(ARG_VBSCRIPT, StringComparison.OrdinalIgnoreCase))
                {
                    timestampObject = new TextFileTimestamp(traits: new VbscriptSignatureTraits());
                }
                else if (args[argIndex].Equals(ARG_SERVER_URI, StringComparison.OrdinalIgnoreCase))
                {
                    argIndex++;
                    if (argIndex >= args.Length)
                    {
                        Console.WriteLine($"[ERROR] Expecting argument for {ARG_SERVER_URI}\n----\n");
                        Usage();
                        return -1;
                    }
                    timestampServerUri = args[argIndex];
                }
                else if (args[argIndex].Equals(ARG_DIGESTMETHOD, StringComparison.OrdinalIgnoreCase))
                {
                    argIndex++;
                    if (argIndex >= args.Length)
                    {
                        Console.WriteLine($"[ERROR] Expecting argument for {ARG_DIGESTMETHOD}\n----\n");
                        Usage();
                        return -1;
                    }
                    digestAlgorithm = args[argIndex];
                }
                else if (args[argIndex].Equals(ARG_SIGNTOOL_PATH, StringComparison.OrdinalIgnoreCase))
                {
                    argIndex++;
                    if (argIndex >= args.Length)
                    {
                        Console.WriteLine($"[ERROR] Expecting argument for {ARG_SIGNTOOL_PATH}\n----\n");
                        Usage();
                        return -1;
                    }
                    signToolPath = args[argIndex];
                }
                else
                {
                    if (!System.IO.File.Exists(args[argIndex]))
                    {
                        Console.WriteLine($"[ERROR] File {args[argIndex]} does not exist. Aborting.");
                        return -1;
                    }
                    fileList.Add(args[argIndex]);
                }
                argIndex++;
            }

            if (timestampObject == null)
            {
                Console.WriteLine($"[ERROR] File type unknown, expecting {ARG_POWERSHELL} or {ARG_VBSCRIPT}\n----\n");
                Usage();
                return -1;
            }
            else if (fileList.Count == 0)
            {
                Console.WriteLine($"[ERROR] No input file specified\n----\n");
                Usage();
                return -1;
            }
            else if(timestampServerUri == null)
            {
                Console.WriteLine("[ERROR] No timestamp server URI specified.\n----\n");
                Usage();
                return -1;
            }

            fileList.ForEach(filePath =>
            {
                Console.WriteLine($"[INFO] About to timestamp file {filePath}\n\tSigntool: {signToolPath}\n\tTimestamp URI: {timestampServerUri}\n\tDigest algorithm: {digestAlgorithm}");
                if (timestampObject.TimestampFile(signToolPath, filePath, timestampServerUri, digestAlgorithm) == 0)
                {
                    successfulList.Add(filePath);
                }
                else
                {
                    Console.WriteLine($"[ERROR] file {filePath} could not be timestamped.");
                    failedList.Add(filePath);
                }
            });

            if (successfulList.Count > 0)
            {
                Console.WriteLine("The following files were successfully timestamped:");
                successfulList.ForEach(filePath => Console.WriteLine($"\t* [SUCCESS] {filePath}"));
            }

            if (failedList.Count > 0)
            {
                Console.WriteLine("[ERROR] The following files could not be timestamped:");
                failedList.ForEach(filePath => Console.WriteLine($"\t* [ERROR]   {filePath}"));
            }

            return 0;
        }
    }
}
