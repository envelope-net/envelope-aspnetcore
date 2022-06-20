using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Envelope.AspNetCore.Authentication;
using Envelope.AspNetCore.Middleware.Authentication;
using Envelope.AspNetCore.Middleware.Authorization;
using Envelope.AspNetCore.Middleware.HostNormalizer;
using Envelope.AspNetCore.Middleware.Initialization;
using Envelope.AspNetCore.Middleware.Tracking;
using Envelope.Extensions;
using Envelope.Localization;
using Envelope.Trace;
using Envelope.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;

namespace Envelope.AspNetCore.Extensions;

public static partial class ServiceCollectionExtensions
{
	public static IServiceCollection AddAspNetApplicationContext(this IServiceCollection services,
		string systemName,
		bool withQueryList = false,
		bool withCookies = true,
		bool withHeaders = true,
		bool withForm = false)
		=> services.AddScoped<IApplicationContext>(sp =>
		{
			var httpContext = sp.GetRequiredService<IHttpContextAccessor>().HttpContext;

			var traceFrame = TraceFrame.Create();
			ITraceInfo traceInfo;

			if (httpContext == null)
			{
				traceInfo = new TraceInfoBuilder(systemName, traceFrame, null)
					.CorrelationId(Guid.NewGuid())
					.ExternalCorrelationId(Guid.NewGuid().ToString("D"))
					.Build();
			}
			else
			{
				traceInfo = new TraceInfoBuilder(systemName, traceFrame, null)
					.CorrelationId(Guid.NewGuid())
					.ExternalCorrelationId(httpContext.TraceIdentifier)
					.Principal(httpContext.User)
					.Build();
			}

			var appResources = sp.GetRequiredService<IApplicationResources>();
			var requsetMetadata = httpContext?.Request.ToRequestMetadata(
				withQueryList: withQueryList,
				withCookies: withCookies,
				withHeaders: withHeaders,
				withForm: withForm,
				cookieDataProtectionPurposes: AuthenticationService.GetDataProtectors(httpContext));
			var appCtx = new ApplicationContext(traceInfo, appResources, requsetMetadata);
			return appCtx;
		});

	public static IServiceCollection AddEnvelopeAuthentication<TAuthMngr, TCookieStore>(this IServiceCollection services, Action<AuthenticationOptions>? configureAuthenticationOptions)
		where TAuthMngr : class, IAuthenticationManager
		where TCookieStore : class, ICookieStore
	{
		services.TryAddSingleton<ICookieStore, TCookieStore>();
		return AddEnvelopeAuthentication<TAuthMngr>(services, configureAuthenticationOptions, null);
	}

	public static IServiceCollection AddEnvelopeAuthentication<TAuthMngr>(this IServiceCollection services, Action<AuthenticationOptions>? configureAuthenticationOptions, ICookieStore? cookieStore = null)
		where TAuthMngr : class, IAuthenticationManager
	{
		if (configureAuthenticationOptions == null)
			return services;

		var authenticationBuilder =
			services.AddAuthentication(opt =>
			{
				opt.DefaultAuthenticateScheme = AuthenticationDefaults.AuthenticationScheme;
				opt.DefaultChallengeScheme = AuthenticationDefaults.AuthenticationScheme;
				opt.DefaultForbidScheme = AuthenticationDefaults.AuthenticationScheme;
			});

		authenticationBuilder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<AuthenticationOptions>, PostConfigureAuthenticationOptions>());
		authenticationBuilder.AddScheme<AuthenticationOptions, EnvelopeAuthenticationHandler>(
			AuthenticationDefaults.AuthenticationScheme,
			displayName: null,
			configureOptions: configureAuthenticationOptions);

		services.AddScoped<IAuthenticationManager, TAuthMngr>();
		services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();

		services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
		services.AddScoped(sp => (sp.GetRequiredService<IHttpContextAccessor>().HttpContext?.User as EnvelopePrincipal) ?? new EnvelopePrincipal());

		if (cookieStore != null)
			services.TryAddSingleton(cookieStore);

		return services;
	}

	public static IServiceCollection ConfigureAspNetMiddlewares<TAuth>(
		this IServiceCollection services,
		string systemName,
		Action<RequestInitializationOptions>? configureRequestInitializationOptions = null,
		Action<ForwardedHeadersOptions>? configureForwardedHeadersOptions = null,
		Action<ExceptionHandlerOptions>? configureExceptionHandlerOptions = null,
		Action<HostNormalizerOptions>? configureHostNormalizerOptions = null,
		Action<RequestTrackingOptions>? configureRequestTracking = null,
		Action<AuthenticationOptions>? configureAuthenticationOptions = null)
		where TAuth : class, IAuthenticationManager
	{
		AddAspNetApplicationContext(services, systemName);

		if (configureRequestInitializationOptions != null)
			services.Configure(configureRequestInitializationOptions);

		if (configureForwardedHeadersOptions != null)
			services.Configure(configureForwardedHeadersOptions);

		if (configureExceptionHandlerOptions != null)
			services.Configure(configureExceptionHandlerOptions);

		if (configureHostNormalizerOptions != null)
			services.Configure(configureHostNormalizerOptions);

		if (configureRequestTracking != null)
			services.Configure(configureRequestTracking);

		if (configureAuthenticationOptions != null)
			AddEnvelopeAuthentication<TAuth>(services, configureAuthenticationOptions, null);

		return services;
	}
}
