using System.Runtime.Versioning;

// Every P/Invoke surface in this project (clipboard, session, DPAPI, registry) is
// Windows-only. The build still cross-compiles on macOS/Linux for CI convenience;
// only execution requires Windows.
[assembly: SupportedOSPlatform("windows")]
