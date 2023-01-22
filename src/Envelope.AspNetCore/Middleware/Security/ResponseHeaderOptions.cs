using Envelope.Extensions;
using Microsoft.AspNetCore.Http;
using System.IO;
using static Envelope.AspNetCore.Middleware.Security.ResponseHeaderOptions;

namespace Envelope.AspNetCore.Middleware.Security;

#if NET6_0_OR_GREATER
[Envelope.Serializer.JsonPolymorphicConverter]
#endif
public interface IResponseHeaderOptions
{
	bool Remove { get; }
	string Key { get; }
	string? Value { get; }
	Protocol ApplyToProtocol { get; }
	IReadOnlyList<string>? ApplyOnlyToContentTypes { get; }
	IReadOnlyList<string>? AllowedPaths { get; }
	IReadOnlyList<string>? IgnoredPaths { get; }

	ResponseHeaderOptions ApplyToContentType(string contentType);
	ResponseHeaderOptions AllowOnlyPath(string path);
	ResponseHeaderOptions IgnoredPath(params string[] paths);
}

public class ResponseHeaderOptions : IResponseHeaderOptions
{
	public enum Protocol
	{
		http = 1,
		https = 2,
		httpAndHttps = http & https
	}

	public bool Remove { get; }
	public string Key { get; set; }
	public string? Value { get; set; }
	public Protocol ApplyToProtocol { get; set; }
	public List<string>? ApplyOnlyToContentTypes { get; set; }
	IReadOnlyList<string>? IResponseHeaderOptions.ApplyOnlyToContentTypes => ApplyOnlyToContentTypes;
	public List<string>? AllowedPaths { get; set; }
	IReadOnlyList<string>? IResponseHeaderOptions.AllowedPaths => AllowedPaths;
	public List<string>? IgnoredPaths { get; set; }
	IReadOnlyList<string>? IResponseHeaderOptions.IgnoredPaths => IgnoredPaths;

	public ResponseHeaderOptions(string key, string? value, Protocol applyToProtocol = Protocol.httpAndHttps)
	{
		Key = string.IsNullOrWhiteSpace(key)
			? throw new ArgumentNullException(nameof(key))
			: key;
		Value = value;
		ApplyToProtocol = applyToProtocol;
		Remove = string.IsNullOrWhiteSpace(value);
	}

	public ResponseHeaderOptions ApplyToContentType(string contentType)
	{
		if (string.IsNullOrWhiteSpace(contentType))
			return this;

		ApplyOnlyToContentTypes ??= new List<string>();
		ApplyOnlyToContentTypes.AddUniqueItem(contentType);
		return this;
	}

	public ResponseHeaderOptions AllowOnlyPath(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
			return this;

		AllowedPaths ??= new List<string>();
		AllowedPaths.AddUniqueItem(path);
		return this;
	}

	public ResponseHeaderOptions IgnoredPath(params string[] paths)
	{
		if (paths == null || paths.Length == 0)
			return this;

		IgnoredPaths ??= new List<string>();
		IgnoredPaths.AddUniqueRange(paths.Where(x => !string.IsNullOrWhiteSpace(x)));
		return this;
	}

	private static bool IsAllowedPath(string path, IResponseHeaderOptions options)
	{
		if (options.IgnoredPaths == null || options.IgnoredPaths.Count == 0)
		{
			if (options.AllowedPaths == null || options.AllowedPaths.Count == 0)
			{
				return true;
			}
			else
			{
				foreach (var allowedPath in options.AllowedPaths)
					if (path.StartsWith(allowedPath))
						return true;

				return false;
			}
		}
		else
		{
			foreach (var ignoredPath in options.IgnoredPaths)
				if (path.StartsWith(ignoredPath))
					return false;

			return true;
		}
	}

	internal static void Apply(HttpContext context, IResponseHeaderOptions options)
	{
		var request = context.Request;
		var path = request.Path;

		var headers = context.Response.Headers;

		if (request.IsHttps)
		{
			if (options.ApplyToProtocol == Protocol.https || options.ApplyToProtocol == Protocol.httpAndHttps)
			{
				if (options.Remove)
				{
					if (options.ApplyOnlyToContentTypes == null || options.ApplyOnlyToContentTypes.Count == 0)
					{
						if (IsAllowedPath(path, options))
							headers.Remove(options.Key);
					}
					else
					{
						if (string.IsNullOrWhiteSpace(context.Response.ContentType))
						{
							if (IsAllowedPath(path, options))
								headers.Remove(options.Key);
						}
						else
						{
							foreach (var contentType in options.ApplyOnlyToContentTypes)
							{
								if (context.Response.ContentType.StartsWith(contentType))
								{
									if (IsAllowedPath(path, options))
										headers.Remove(options.Key);

									break;
								}
							}
						}
					}
				}
				else
				{
					if (options.ApplyOnlyToContentTypes == null || options.ApplyOnlyToContentTypes.Count == 0)
					{
						if (IsAllowedPath(path, options))
							headers[options.Key] = options.Value;
					}
					else
					{
						if (string.IsNullOrWhiteSpace(context.Response.ContentType))
						{
							if (IsAllowedPath(path, options))
								headers[options.Key] = options.Value;
						}
						else
						{
							foreach (var contentType in options.ApplyOnlyToContentTypes)
							{
								if (context.Response.ContentType.StartsWith(contentType))
								{
									if (IsAllowedPath(path, options))
										headers[options.Key] = options.Value;

									break;
								}
							}
						}
					}
				}
			}
		}
		else
		{
			if (options.ApplyToProtocol == Protocol.http || options.ApplyToProtocol == Protocol.httpAndHttps)
			{
				if (options.Remove)
				{
					if (options.ApplyOnlyToContentTypes == null || options.ApplyOnlyToContentTypes.Count == 0)
					{
						if (IsAllowedPath(path, options))
							headers.Remove(options.Key);
					}
					else
					{
						if (string.IsNullOrWhiteSpace(context.Response.ContentType))
						{
							if (IsAllowedPath(path, options))
								headers.Remove(options.Key);
						}
						else
						{
							foreach (var contentType in options.ApplyOnlyToContentTypes)
							{
								if (context.Response.ContentType.StartsWith(contentType))
								{
									if (IsAllowedPath(path, options))
										headers.Remove(options.Key);

									break;
								}
							}
						}
					}
				}
				else
				{
					if (options.ApplyOnlyToContentTypes == null || options.ApplyOnlyToContentTypes.Count == 0)
					{
						if (IsAllowedPath(path, options))
							headers[options.Key] = options.Value;
					}
					else
					{
						if (string.IsNullOrWhiteSpace(context.Response.ContentType))
						{
							if (IsAllowedPath(path, options))
								headers[options.Key] = options.Value;
						}
						else
						{
							foreach (var contentType in options.ApplyOnlyToContentTypes)
							{
								if (context.Response.ContentType.StartsWith(contentType))
								{
									if (IsAllowedPath(path, options))
										headers[options.Key] = options.Value;

									break;
								}
							}
						}
					}
				}
			}
		}
	}

	public static IResponseHeaderOptions RemoveSerever { get; } =
		new ResponseHeaderOptions("Server", null, Protocol.httpAndHttps);

	public static IResponseHeaderOptions ReferrerPolicy { get; } =
		new ResponseHeaderOptions("referrer-policy", "strict-origin-when-cross-origin", Protocol.httpAndHttps)
		.ApplyToContentType("text/html");

	public static IResponseHeaderOptions XContentTypeOptions { get; } =
		new ResponseHeaderOptions("x-content-type-options", "nosniff", Protocol.httpAndHttps);

	public static IResponseHeaderOptions XFrameOptions_DENY { get; } =
		new ResponseHeaderOptions("x-frame-options", "DENY", Protocol.httpAndHttps)
			.ApplyToContentType("text/html");

	public static IResponseHeaderOptions XFrameOptions_SAMEORIGIN { get; } =
		new ResponseHeaderOptions("x-frame-options", "SAMEORIGIN", Protocol.httpAndHttps)
			.ApplyToContentType("text/html");

	public static IResponseHeaderOptions XPermittedCrossDomainPolicies { get; } =
		new ResponseHeaderOptions("X-Permitted-Cross-Domain-Policies", "none", Protocol.httpAndHttps);

	public static IResponseHeaderOptions XXssProtection { get; } =
		new ResponseHeaderOptions("x-xss-protection", "1; mode=block", Protocol.httpAndHttps)
		.ApplyToContentType("text/html");

	public static IResponseHeaderOptions ExpectCT { get; } =
		new ResponseHeaderOptions("Expect-CT", "max-age=0, enforce, report-uri=\"https://example.report-uri.com/r/d/ct/enforce\"", Protocol.httpAndHttps);

	public static IResponseHeaderOptions FeaturePolicy { get; } =
		new ResponseHeaderOptions(
			"Feature-Policy",
			"accelerometer 'none';" +
				"ambient-light-sensor 'none';" +
				"autoplay 'none';" +
				"battery 'none';" +
				"camera 'none';" +
				"display-capture 'none';" +
				"document-domain 'none';" +
				"encrypted-media 'none';" +
				"execution-while-not-rendered 'none';" +
				"execution-while-out-of-viewport 'none';" +
				"gyroscope 'none';" +
				"magnetometer 'none';" +
				"microphone 'none';" +
				"midi 'none';" +
				"navigation-override 'none';" +
				"payment 'none';" +
				"picture-in-picture 'none';" +
				"publickey-credentials-get 'none';" +
				"sync-xhr 'none';" +
				"usb 'none';" +
				"wake-lock 'none';" +
				"xr-spatial-tracking 'none';",
			Protocol.httpAndHttps)
			.ApplyToContentType("text/html");

	public static IResponseHeaderOptions ContentSecurityPolicy { get; } =
		new ResponseHeaderOptions(
			"Content-Security-Policy",
			"base-uri 'none';" +
				"block-all-mixed-content;" +
				"child-src 'none';" +
				"connect-src 'none';" +
				"default-src 'none';" +
				"font-src 'none';" +
				"form-action 'none';" + //self
				"frame-ancestors 'none';" +
				"frame-src 'none';" +  ////////////////////because the document's frame is sandboxed and the 'allow-scripts' permission is not set.
				"img-src 'none';" + //ee
				"manifest-src 'none';" +
				"media-src 'none';" +
				"object-src 'none';" +
				"sandbox;" +
				"script-src 'none';" +
				"script-src-attr 'none';" +
				"script-src-elem 'none';" +
				"style-src 'none';" +
				"style-src-attr 'none';" +
				"style-src-elem 'none';" + //ee .... unsafe-inline OR nonce
				"upgrade-insecure-requests;" +
				"worker-src 'none';",
			Protocol.httpAndHttps)
			.ApplyToContentType("text/html");
}
