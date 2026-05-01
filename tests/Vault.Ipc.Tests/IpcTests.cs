using Xunit;

namespace Vault.Ipc.Tests;

public class NativeMessagingFramingTests
{
    [Fact]
    public async Task Round_trip_request_response()
    {
        var request = new IpcRequest
        {
            ProtocolVersion = 1,
            Id = "abc-123",
            Type = IpcMessageTypes.FindCredentials,
            Url = "https://example.com/login",
        };

        // Write to a memory stream simulating stdin/stdout from native side.
        using var requestStream = new MemoryStream();
        // Manually frame: 4 bytes LE length + JSON.
        var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(request, IpcJsonContext.Default.IpcRequest);
        var len = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(len, json.Length);
        requestStream.Write(len);
        requestStream.Write(json);
        requestStream.Position = 0;

        var read = await NativeMessagingFraming.ReadAsync(requestStream);
        Assert.NotNull(read);
        Assert.Equal(request.Id, read.Id);
        Assert.Equal(request.Type, read.Type);
        Assert.Equal(request.Url, read.Url);
    }

    [Fact]
    public async Task Read_returns_null_on_EOF()
    {
        using var empty = new MemoryStream();
        Assert.Null(await NativeMessagingFraming.ReadAsync(empty));
    }

    [Fact]
    public async Task Read_throws_on_oversized_length()
    {
        using var ms = new MemoryStream();
        var bad = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bad, NativeMessagingFraming.MaxBrowserToHost + 1);
        ms.Write(bad);
        ms.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await NativeMessagingFraming.ReadAsync(ms));
    }

    [Fact]
    public async Task Write_rejects_response_too_large_for_browser()
    {
        using var ms = new MemoryStream();
        var huge = new IpcResponse
        {
            Id = "x",
            Ok = true,
            Error = new string('x', NativeMessagingFraming.MaxHostToBrowser),
        };
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await NativeMessagingFraming.WriteAsync(ms, huge));
    }
}

public class PublicSuffixTests
{
    [Theory]
    [InlineData("google.com", "google.com")]
    [InlineData("accounts.google.com", "google.com")]
    [InlineData("foo.bar.baz.google.com", "google.com")]
    [InlineData("example.org", "example.org")]
    public void Common_TLDs_resolve(string host, string expected)
    {
        var actual = PublicSuffix.GetRegistrableDomain(host);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Same_site_matches_subdomains()
    {
        Assert.True(PublicSuffix.SameSite(
            "https://accounts.google.com/signin",
            "https://mail.google.com/inbox"));
    }

    [Fact]
    public void Same_site_rejects_different_sites()
    {
        Assert.False(PublicSuffix.SameSite(
            "https://google.com",
            "https://google-impostor.com"));
    }

    [Fact]
    public void Bare_TLD_returns_null()
    {
        // "com" alone is a public suffix with no registrable part.
        Assert.Null(PublicSuffix.GetRegistrableDomain("com"));
    }

    [Fact]
    public void Extract_host_handles_naked_input()
    {
        Assert.Equal("google.com", PublicSuffix.ExtractHost("google.com"));
        Assert.Equal("google.com", PublicSuffix.ExtractHost("https://google.com/"));
        Assert.Equal("google.com", PublicSuffix.ExtractHost("https://google.com:8443/path"));
    }
}
