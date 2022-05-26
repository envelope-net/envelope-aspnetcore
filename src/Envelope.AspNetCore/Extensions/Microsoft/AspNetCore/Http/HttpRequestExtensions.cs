using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Envelope.Web;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http;

namespace Envelope.Extensions;

public static class HttpRequestExtensions
{
	[return: NotNullIfNotNull("request")]
	public static Uri? GetUri(this HttpRequest request)
	{
		if (request == null)
			return null;

		//string absoluteUri = $"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}";
		//Uri uri = new Uri(absoluteUri);
		//return uri;

		var hostComponents = request.Host.ToUriComponent().Split(':');

		var uriBuilder = new UriBuilder
		{
			Scheme = request.Scheme,
			Host = hostComponents[0],
			Path = string.Concat(request.PathBase.ToUriComponent(), request.Path.ToUriComponent()), //Request.PathBase reprezentuje VIRTUAL PATH = VirtualPath
			Query = request.QueryString.ToUriComponent()
		};

		if (hostComponents.Length == 2)
		{
			uriBuilder.Port = Convert.ToInt32(hostComponents[1]);
		}

		return uriBuilder.Uri;
	}

	[return: NotNullIfNotNull("request")]
	public static IRequestMetadata? ToRequestMetadata(
		this HttpRequest request,
		bool withQueryList = false,
		bool withCookies = true,
		bool withHeaders = true,
		bool withForm = false,
		IReadOnlyDictionary<string, IDataProtector>? cookieDataProtectionPurposes = null //Dictionary<cookieName, IDataProtector>
		)
	{
		if (request == null)
			return null;

		var queryList = withQueryList
			? request.Query.Select(x => new KeyValuePair<string, List<string>>(x.Key, new List<string>(x.Value))).ToList()
			: null;

		var cookiesList = withCookies
			? request.Cookies.Select(x => new KeyValuePair<string, string>(x.Key, x.Value)).ToList()
			: null;

		var headersDict = withHeaders
			? request.Headers.ToDictionary(k => k.Key, v => new List<string>(v.Value))
			: null;

		var formList = withForm
			? (request.HasFormContentType
				? request.Form.Select(x => new KeyValuePair<string, List<string>>(x.Key, new List<string>(x.Value))).ToList()
				: new List<KeyValuePair<string, List<string>>>())
			: null;

		Dictionary<string, Func<string, string>>? cookieUnprotectors = null;
		if (cookieDataProtectionPurposes != null && 0 < cookieDataProtectionPurposes.Count)
		{
			cookieUnprotectors = new Dictionary<string, Func<string, string>>();

			foreach (var kvp in cookieDataProtectionPurposes)
			{
				var dataProtector = kvp.Value;
				cookieUnprotectors.Add(
					kvp.Key,
					cookieValue => System.Text.Encoding.UTF8.GetString(dataProtector.Unprotect(WebEncoders.Base64UrlDecode(cookieValue))));
			}
		}

		return new RequestMetadata
		{
			Query = queryList,
			ContentType = request.ContentType,
			ContentLength = request.ContentLength,
			Cookies = cookiesList,
			Headers = headersDict,
			Protocol = request.Protocol,
			RouteValues = request.RouteValues.ToDictionary(x => x.Key, x => x.Value),
			Path = request.Path,
			PathBase = request.PathBase,
			Host = request.Host.Host,
			RemoteIp = request.HttpContext.Connection?.RemoteIpAddress?.ToString(),
			Port = request.Host.Port,
			Uri = request.GetUri(),
			Scheme = request.Scheme,
			Method = request.Method,
			Form = formList,
			FilesCount = withForm ? (request.HasFormContentType ? request.Form.Files.Count : 0) : null,
			CookieUnprotectors = cookieUnprotectors,
			RequestServiceProvider = request.HttpContext.RequestServices
		};
	}
}
