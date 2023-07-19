using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace PowershellScriptTimestamp
{
    internal class TextFileTimestamp
    {
        public TextFileTimestamp(IAuthenticodeSignatureTraits traits)
        {
            _traits = traits;
        }

        private readonly IAuthenticodeSignatureTraits _traits;

        /// <summary>
        /// Indicates the byte format of the signature.
        /// </summary>
        /// <remarks>
        /// Powershell and vbs signature ALWAYS uses CRLF as a line terminator.
        /// It is advised to always use CRLF for Powershell and vbs scripts.
        /// Moreover, their signature block is encoded either in pure ASCII, or in UTF-16le.
        /// </remarks>
        private enum ETextFileEncodingType
        {
            /// <summary>
            /// The signature is ASCII-encoded
            /// </summary>
            OneByte,
            /// <summary>
            /// The signature is UTF-16LE-encoded
            /// </summary>
            Utf16Le,
        }

        /// <summary>
        /// Represents a text file of signable format, deassembled
        /// </summary>
        private class SignedFileParts
        {
            /// <summary>
            /// Used when reassembling the script: indicates how to encode the signature
            /// </summary>
            public ETextFileEncodingType encodingType;

            /// <summary>
            /// Bytes before the signature block, raw (this also can include BOM)
            /// </summary>
            public byte[] rawBytesBeforeSignature;

            /// <summary>
            /// Binary representation of the signature. This is a byte sequence representing a DER-encoded PKCS#7 bundle.
            /// </summary>
            public byte[] rawPkcs7SignatureBytes;

            /// <summary>
            /// Bytes after the signature block, raw (always observed to be empty)
            /// </summary>
            public byte[] rawBytesAfterSignature;
        }

        /// <summary>
        /// Extract the parts of a signed file such that the signature block can be amended.
        /// </summary>
        /// <param name="filePath">Path to the file</param>
        /// <returns>Deassembled file</returns>
        private SignedFileParts DeassembleSignedFile(string filePath)
        {
            var deassembledScript = new SignedFileParts();
            byte[] originalFileBytes = File.ReadAllBytes(filePath);

            deassembledScript.encodingType = ETextFileEncodingType.OneByte;
            int codeUnitByteLength = 1;
            if (originalFileBytes.Length > 2 && originalFileBytes[0] == 0xFF && originalFileBytes[1] == 0xFE)
            {
                // We have a Byte order mark. The only possible encoding is UTF-16, Little Endian.
                deassembledScript.encodingType = ETextFileEncodingType.Utf16Le;
                codeUnitByteLength = 2;
            }

            byte[] SIGNATURE_BEGIN_SEQUENCE = deassembledScript.encodingType == ETextFileEncodingType.OneByte ?
                                                    System.Text.Encoding.UTF8.GetBytes(_traits.SignatureBeginSequence) :
                                                    System.Text.Encoding.Unicode.GetBytes(_traits.SignatureBeginSequence);

            byte[] SIGNATURE_END_SEQUENCE = deassembledScript.encodingType == ETextFileEncodingType.OneByte ?
                                                  System.Text.Encoding.UTF8.GetBytes(_traits.SignatureEndSequence) :
                                                  System.Text.Encoding.Unicode.GetBytes(_traits.SignatureEndSequence);

            int signatureBeginOffset = 0;
            for (bool beginSignatureFound = false; !beginSignatureFound;)
            {
                // Non-optimized subarray search algorithm. Could be replaced by Boyer-Moore if performance is necessary.
                for (int searchPosition = 0; searchPosition < originalFileBytes.Length; searchPosition += codeUnitByteLength)
                {
                    if (originalFileBytes.Skip(searchPosition).Take(SIGNATURE_BEGIN_SEQUENCE.Length).SequenceEqual(SIGNATURE_BEGIN_SEQUENCE))
                    {
                        beginSignatureFound = true;
                        signatureBeginOffset = searchPosition + SIGNATURE_BEGIN_SEQUENCE.Length;
                        deassembledScript.rawBytesBeforeSignature = originalFileBytes.Take(searchPosition).ToArray();
                        break;
                    }
                }
                if (!beginSignatureFound)
                {
                    if (deassembledScript.encodingType == ETextFileEncodingType.OneByte)
                    {
                        // Maybe the script is UTF-16LE encoded, but does not have a BOM. Retrying.
                        Console.WriteLine($"[WARN] Signature block not found in one-byte encoding. Retrying, assuming UTF-16LE without BOM.");
                        SIGNATURE_BEGIN_SEQUENCE = System.Text.Encoding.Unicode.GetBytes(_traits.SignatureBeginSequence);
                        SIGNATURE_END_SEQUENCE = System.Text.Encoding.Unicode.GetBytes(_traits.SignatureEndSequence);
                        codeUnitByteLength = 2;
                        deassembledScript.encodingType = ETextFileEncodingType.Utf16Le;
                    }
                    else
                    {
                        Console.WriteLine($"[ERROR] Signature block not found.");
                        return null;
                    }
                }
            }

            int signatureEndOffset = 0;
            bool endSignatureFound = false;
            for (int searchPosition = signatureBeginOffset; searchPosition < originalFileBytes.Length; searchPosition += codeUnitByteLength)
            {
                if (originalFileBytes.Skip(searchPosition).Take(SIGNATURE_END_SEQUENCE.Length).SequenceEqual(SIGNATURE_END_SEQUENCE))
                {
                    endSignatureFound = true;
                    signatureEndOffset = searchPosition;
                    deassembledScript.rawBytesAfterSignature = originalFileBytes.Skip(searchPosition + SIGNATURE_END_SEQUENCE.Length).ToArray();
                    break;
                }
            }
            if (!endSignatureFound)
            {
                Console.WriteLine($"[ERROR] End of signature block not found.");
                return null;
            }

            try
            {
                byte[] signatureSectionAsBytes = originalFileBytes.Skip(signatureBeginOffset).Take(signatureEndOffset - signatureBeginOffset).ToArray();

                string signatureLines = deassembledScript.encodingType == ETextFileEncodingType.OneByte ?
                    System.Text.Encoding.UTF8.GetString(signatureSectionAsBytes) :
                    System.Text.Encoding.Unicode.GetString(signatureSectionAsBytes);

                string wholeSignatureBase64 =
                    new string(signatureLines.Split(separator: new string[] { _traits.SignatureLineEnding }, options: StringSplitOptions.None)
                                             .Select(line =>
                                             {
                                                 if (line.StartsWith(_traits.SignatureLineBeginning, StringComparison.Ordinal))
                                                 {
                                                     return line.Substring(_traits.SignatureLineBeginning.Length);
                                                 }
                                                 return line;
                                             })
                                             .Aggregate("", (s, line) => s + line)
                                             .Where(c =>
                                             {
                                                 return (char.IsLetterOrDigit(c) && c <= 0x7F) // ASCII chiffers and letters
                                                     || c == '/'
                                                     || c == '+'
                                                     || c == '=';
                                             })
                                             .ToArray());

                deassembledScript.rawPkcs7SignatureBytes = Convert.FromBase64String(wholeSignatureBase64);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] Could not convert signature lines from Base64. Dumping exception.");
                Console.WriteLine(ex);
                return null;
            }

            return deassembledScript;
        }

        /// <summary>
        /// Split a string in portions of up to <paramref name="chunkSize"/> code units
        /// </summary>
        /// <param name="stringToSplit">String to split</param>
        /// <param name="chunkSize">chunk size</param>
        /// <returns>enumeration of chunks</returns>
        private static IEnumerable<string> ChunkifyString(string stringToSplit, int chunkSize)
        {
            int offset = 0;
            while (offset < stringToSplit.Length)
            {
                yield return stringToSplit.Substring(offset, Math.Min(chunkSize, stringToSplit.Length - offset));
                offset += chunkSize;
            }
            yield break;
        }

        /// <summary>
        /// Rewrite signed file with PKCS#7 block modified
        /// </summary>
        /// <param name="fileParts">Deassembled file</param>
        /// <param name="outputPath">Output file path</param>
        private bool ReassembleSignedFileFromParts(SignedFileParts fileParts, string outputPath)
        {
            var base64EncodedSignature = System.Convert.ToBase64String(fileParts.rawPkcs7SignatureBytes);

            // signature lines consist of comment mark, space, and up to 64 base64 characters.
            IEnumerable<string> signatureLines = ChunkifyString(base64EncodedSignature, _traits.SignatureCharsPerLine).Select(line => _traits.SignatureLineBeginning + line);

            string signatureBlock = _traits.SignatureBeginSequence +
                                    String.Join(_traits.SignatureLineEnding, signatureLines) +
                                    _traits.SignatureEndSequence;

            byte[] signatureBytes = fileParts.encodingType == ETextFileEncodingType.OneByte ?
                     System.Text.Encoding.UTF8.GetBytes(signatureBlock) :
                     System.Text.Encoding.Unicode.GetBytes(signatureBlock);

            try
            {
                File.WriteAllBytes(
                    outputPath,
                    fileParts.rawBytesBeforeSignature
                          .Concat(signatureBytes)
                          .Concat(fileParts.rawBytesAfterSignature)
                          .ToArray());
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Could not overwrite script {outputPath}. Dumping exception.");
                Console.WriteLine(ex);
                return false;
            }

            return true;
        }

        private bool TimestampPKCS7File(string signToolPath, string pkcs7FilePath, string timestampServerUri, string digestAlgorithm)
        {
            var signToolResult = new ProcessExecutionResult(
                signToolPath,
                string.Format("timestamp /v /tr \"{0}\" /td {1} /p7 \"{2}\"", timestampServerUri, digestAlgorithm, pkcs7FilePath)
                );

            if (!signToolResult.Successful)
            {
                Console.WriteLine($"[ERROR] Could not timestamp PKCS#7 file ${pkcs7FilePath}.");
                return false;
            }
            return signToolResult.ExitCode == 0;
        }

        /// <summary>
        /// Timestamp a signed text file.
        /// </summary>
        /// <param name="signToolPath">Path to signtool.exe</param>
        /// <param name="filePath">Path to the file to sign</param>
        /// <param name="timestampServerUri">URI of a RFC 3161 timestamp server</param>
        /// <param name="digestAlgorithm">Method for digest, passed to signtool timestamp subcommand</param>
        /// <returns></returns>
        public int TimestampFile(string signToolPath, string filePath, string timestampServerUri, string digestAlgorithm)
        {
            string temporaryPkcs7SignatureBlockPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".p7");
            try
            {
                SignedFileParts script = DeassembleSignedFile(filePath);
                if (script == null)
                {
                    Console.WriteLine($"[ERROR] Could not deassemble script ${filePath}.");
                    return -1;
                }

                try
                {
                    File.WriteAllBytes(temporaryPkcs7SignatureBlockPath, script.rawPkcs7SignatureBytes);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Could not extract signature PKCS#7 block from file ${filePath} to file {temporaryPkcs7SignatureBlockPath}. Dumping exception.");
                    Console.WriteLine(ex);
                    return -1;
                }

                if (!TimestampPKCS7File(signToolPath, temporaryPkcs7SignatureBlockPath, timestampServerUri, digestAlgorithm))
                {
                    Console.WriteLine($"[ERROR] Could not timestamp PKCS#7 file ${temporaryPkcs7SignatureBlockPath} with URI {timestampServerUri}.");
                    return -1;
                }

                try
                {
                    script.rawPkcs7SignatureBytes = File.ReadAllBytes(temporaryPkcs7SignatureBlockPath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] Could not read file ${temporaryPkcs7SignatureBlockPath} after timestamp operation. Dumping exception.");
                    Console.WriteLine(ex);
                    return -1;
                }

                if (!ReassembleSignedFileFromParts(script, filePath))
                {
                    Console.WriteLine($"[ERROR] Could not re-assemble file ${filePath} with signature from file {temporaryPkcs7SignatureBlockPath}.");
                    return -1;
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] An unhandle error occurred while timestamping file {filePath}. Dumping exception.");
                Console.WriteLine(ex);
                return -1;
            }
            finally
            {
                try
                {
                    File.Delete(temporaryPkcs7SignatureBlockPath);
                }
                catch
                {
                    Console.WriteLine($"[WARN] The temporary file {temporaryPkcs7SignatureBlockPath} could not be deleted.");
                }
            }
        }
    }
}
