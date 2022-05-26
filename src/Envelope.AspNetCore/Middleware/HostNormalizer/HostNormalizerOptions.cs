namespace Envelope.AspNetCore.Middleware.HostNormalizer;

public class HostNormalizerOptions
{
	public string? Host { get; set; }
	public string? Protocol { get; set; }
	public string? VirtualPath { get; set; }
}
