(C) 2023 Stormshield

PowershellScriptTimestamp - Utility to timestamp the last Authenticode signature
   on a PowerShell (or VBScript) file.

USAGE
-----

(note: in this section the caret (^) is used as EOL escape character, as in batch files)

For PowerShell files:

PowershellScriptTimestamp.exe               ^
         /powershell                        ^
         /uri <server_uri>                  ^
         [/digest <alg>]                    ^
         [/signtool <path_to_signtool.exe>] ^
         file.ps1 [...]

For VBScript files: replace /powershell with /vbscript

Remarks:
 * <server_uri> should be the URI of a RFC 3161 timestamp server
 * If the path to signtool.exe is not specified, the program will run signtool.exe and
   expect it to be resolved using the PATH environment variable
 * The default digest algorithm value is sha256. Supported values are the same as for
   signtool.

FAQ
---

Q. Do you accept pull requests?
A. They are welcome and will be reviewed.
