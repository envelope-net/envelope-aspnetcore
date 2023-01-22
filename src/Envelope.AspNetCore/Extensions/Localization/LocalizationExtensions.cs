using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Globalization;

namespace Envelope.AspNetCore.Extensions.Localization;

public static class LocalizationExtensions
{
	public static IServiceCollection AddRequestLocalization(this IServiceCollection services, string defaultCulture, params string[] cultures)
	{
		return services.AddRequestLocalization(defaultCulture, null, cultures);
	}

	public static IServiceCollection AddRequestLocalization(this IServiceCollection services, string defaultCulture, Func<HttpContext, string?>? defaultCultureGetter, params string[] cultures)
	{
		string defaultCulture2 = defaultCulture;
		Func<HttpContext, string?> defaultCultureGetter2 = defaultCultureGetter;
		if (services == null)
		{
			throw new ArgumentNullException("services");
		}

		if (string.IsNullOrWhiteSpace(defaultCulture2))
		{
			throw new ArgumentNullException(defaultCulture2);
		}

		List<string> list = cultures?.Distinct().ToList() ?? new List<string>();
		if (!list.Contains(defaultCulture2))
		{
			list.Add(defaultCulture2);
		}

		List<CultureInfo> supportedCultures = list.Select((x) => new CultureInfo(x)).ToList();
		foreach (CultureInfo item in supportedCultures.Where((x) => x.TwoLetterISOLanguageName.Equals("sk", StringComparison.OrdinalIgnoreCase)))
		{
			item.DateTimeFormat.ShortDatePattern = "dd.MM.yyyy";
			item.DateTimeFormat.ShortTimePattern = "HH:mm";
			item.DateTimeFormat.LongTimePattern = "HH:mm:ss";
			item.DateTimeFormat.FullDateTimePattern = "dd.MM.yyyy HH:mm:ss";
		}

		CultureInfo defaultCultureInfo = supportedCultures.First((x) => x.Name.Equals(defaultCulture2, StringComparison.OrdinalIgnoreCase));
		services.Configure(delegate (RequestLocalizationOptions x)
		{
			x.DefaultRequestCulture = new RequestCulture(defaultCultureInfo);
			x.SupportedCultures = supportedCultures.OrderBy((c) => c.EnglishName).ToList();
			x.SupportedUICultures = supportedCultures.OrderBy((c) => c.EnglishName).ToList();
			x.RequestCultureProviders.Insert(0, new RouteValueRequestCultureProvider(defaultCulture2, supportedCultures, defaultCultureGetter2));
		});
		services.AddLocalization();
		services.AddSingleton<IUrlHelperFactory, CultureUrlHelperFactory>();
		return services;
	}

	public static IMvcBuilder AddRequestLocalization(this IMvcBuilder builder, string defaultCulture, params string[] cultures)
	{
		return builder.AddRequestLocalization(defaultCulture, null, cultures);
	}

	public static IMvcBuilder AddRequestLocalization(this IMvcBuilder builder, string defaultCulture, Func<HttpContext, string?>? defaultCultureGetter, params string[] cultures)
	{
		if (builder == null)
			throw new ArgumentNullException(nameof(builder));

		builder.Services.AddRequestLocalization(defaultCulture, defaultCultureGetter, cultures);
		builder.AddRazorPagesOptions(delegate (RazorPagesOptions x)
		{
			x.Conventions.Add(new CultureRouteModelConvention());
		});
		return builder;
	}
}
