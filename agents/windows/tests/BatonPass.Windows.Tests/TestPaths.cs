namespace BatonPass.Windows.Tests;

/// Locates files in the repo (crypto/vectors.json) without hardcoding a path
/// tied to the build output layout, and without copying/editing anything
/// under crypto/ — T6's brief requires reading, never touching, that directory.
internal static class TestPaths
{
    public static string RepoFile(string relativeFromRepoRoot)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, relativeFromRepoRoot);
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException($"could not locate {relativeFromRepoRoot} above {AppContext.BaseDirectory}");
    }
}
