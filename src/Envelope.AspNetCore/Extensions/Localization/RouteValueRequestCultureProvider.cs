using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using System.Globalization;

namespace Envelope.AspNetCore.Extensions.Localization;

public class RouteValueRequestCultureProvider : IRequestCultureProvider
{
	public const string ROUTE_VALUE_PARAMETER = "culture";

	private readonly string _default;

	private readonly Func<HttpContext, string?>? _defaultGetter;

	private readonly CultureInfo[] _cultures;

	public RouteValueRequestCultureProvider(string defaultCulture, IEnumerable<CultureInfo> cultures)
		: this(defaultCulture, cultures, null)
	{
	}

	public RouteValueRequestCultureProvider(string defaultCulture, IEnumerable<CultureInfo> cultures, Func<HttpContext, string?>? defaultCultureGetter)
	{
		if (string.IsNullOrWhiteSpace(defaultCulture))
		{
			throw new ArgumentNullException("defaultCulture");
		}

		_default = defaultCulture;
		_cultures = cultures?.ToArray() ?? throw new ArgumentNullException("cultures");
		_defaultGetter = defaultCultureGetter;
	}

	public Task<ProviderCultureResult> DetermineProviderCultureResult(HttpContext httpContext)
	{
		string[] routeValues = httpContext.Request.Path.Value?.Split('/', StringSplitOptions.RemoveEmptyEntries) ?? new string[0];
		if (routeValues.Length >= 2 && _cultures.Any((x) => x.Name.ToLower() == routeValues[0].ToLower()))
		{
			return Task.FromResult(new ProviderCultureResult(routeValues[0]));
		}

		string text = _defaultGetter?.Invoke(httpContext);
		if (string.IsNullOrWhiteSpace(text))
		{
			text = _default;
		}

		return Task.FromResult(new ProviderCultureResult(text));
	}
}