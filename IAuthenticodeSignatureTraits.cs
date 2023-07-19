namespace PowershellScriptTimestamp
{
    internal interface IAuthenticodeSignatureTraits
    {
        /// <summary>
        /// Code point sequence that is found before every signature
        /// </summary>
        string SignatureBeginSequence { get; }

        /// <summary>
        /// Code point sequence that is found after every signature
        /// </summary>
        string SignatureEndSequence { get; }

        /// <summary>
        /// Code point sequence that is found at the beginning of each signature chunk
        /// </summary>
        string SignatureLineBeginning { get; }

        /// <summary>
        /// Code point sequence that is found at the end of each signature chunk, including the line terminator
        /// </summary>
        string SignatureLineEnding { get; }

        /// <summary>
        /// Number of base64 characters found on each signature chunk.
        /// </summary>
        int SignatureCharsPerLine { get; }
    }
}
