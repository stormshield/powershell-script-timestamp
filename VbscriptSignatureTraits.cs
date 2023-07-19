namespace PowershellScriptTimestamp
{
    internal class VbscriptSignatureTraits : IAuthenticodeSignatureTraits
    {
        /// <summary>
        /// Code point sequence that is found before every signature
        /// </summary>
        string IAuthenticodeSignatureTraits.SignatureBeginSequence => "\r\n'' SIG '' Begin signature block\r\n";

        /// <summary>
        /// Code point sequence that is found after every signature
        /// </summary>
        string IAuthenticodeSignatureTraits.SignatureEndSequence => "\r\n'' SIG '' End signature block\r\n";

        /// <summary>
        /// Code point sequence that is found at the beginning of each signature chunk
        /// </summary>
        string IAuthenticodeSignatureTraits.SignatureLineBeginning => "'' SIG '' ";

        /// <summary>
        /// Code point sequence that is found at the end of each signature chunk, including the line terminator
        /// </summary>
        string IAuthenticodeSignatureTraits.SignatureLineEnding => "\r\n";

        /// <summary>
        /// Number of base64 characters found on each signature chunk.
        /// </summary>
        int IAuthenticodeSignatureTraits.SignatureCharsPerLine => 44;
    }
}
