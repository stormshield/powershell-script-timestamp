using System;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace PowershellScriptTimestamp
{
    internal class ProcessExecutionResult
    {
        public string ExecutablePath { get; }
        public string CommandLineArguments { get; }

        public bool Successful { get; }
        public int ExitCode { get; }

        public string Stdout { get; }
        public string Stderr { get; }


        public ProcessExecutionResult(string path, string arguments)
        {

            ExecutablePath = path;
            CommandLineArguments = arguments;

            var outStringBuilder = new StringBuilder();
            var errStringBuilder = new StringBuilder();
            using (var process = new Process())
                try
                {

                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.Arguments = arguments;
                    process.StartInfo.FileName = path;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.UseShellExecute = false;

                    using (AutoResetEvent stdoutConsumed = new AutoResetEvent(false))
                    using (AutoResetEvent stderrConsumed = new AutoResetEvent(false))
                    {
                        process.OutputDataReceived += (sender, evtArgs) =>
                        {
                            if (evtArgs.Data == null)
                            {
                                stdoutConsumed.Set();
                            }
                            else
                            {
                                outStringBuilder.AppendLine(evtArgs.Data);
                            }
                        };
                        process.ErrorDataReceived += (sender, evtArgs) =>
                        {
                            if (evtArgs.Data == null)
                            {
                                stderrConsumed.Set();
                            }
                            else
                            {
                                errStringBuilder.AppendLine(evtArgs.Data);
                            }
                        };

                        Console.WriteLine($"[INFO] About to run process {path} with arguments {arguments}.");

                        if (!process.Start())
                        {
                            Console.WriteLine($"[ERROR] Could not start process.");
                            return;
                        }

                        try
                        {
                            process.BeginOutputReadLine();
                            process.BeginErrorReadLine();
                            process.WaitForExit();
                            stdoutConsumed.WaitOne();
                            stderrConsumed.WaitOne();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ERROR] Could not wait for end of process. Dumping exception.");
                            Console.WriteLine(ex);
                            return;
                        }
                    }

                    ExitCode = process.ExitCode;
                    Successful = true;

                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Could not run process. Dumping exception.");
                    Console.WriteLine(ex);
                }
                finally
                {
                    Stdout = outStringBuilder.ToString();
                    Stderr = errStringBuilder.ToString();
                }
        }

    }
}
