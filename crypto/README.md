# BatonPass envelope (T1)

`SPEC.md` is normative. `vectors.json` is the conformance suite.

Regenerate vectors (Swift, CryptoKit):

    cd ref-swift && swiftc -O -o gen main.swift && ./gen > ../vectors.json

Verify cross-language agreement (C#, System.Security.Cryptography):

    cd ref-csharp && dotnet run

The C# verifier decrypts every positive vector, checks the plaintext, then
re-seals from the same fixed inputs and requires byte-identical output.
Decrypting proves the format is read correctly; reproducing the bytes proves it
would be written correctly. Negative vectors must all be rejected.

Current: 12 vectors, 12 passing.

Neither implementation takes a third-party crypto dependency. Both use the
platform's standard library.
