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
	public static IServiceCollection AddApplicationContext<TIdentity>(this IServiceCollection services,
		string systemName,
		bool withQueryList = false,
		bool withCookies = true,
		bool withHeaders = true,
		bool withForm = false)
		where TIdentity : struct
		=> services.AddScoped<IApplicationContext<TIdentity>>(sp =>
		{
			var httpContext = sp.GetRequiredService<IHttpContextAccessor>().HttpContext;

			var traceFrame = TraceFrame.Create();
			ITraceInfo<TIdentity> traceInfo;

			if (httpContext == null)
			{
				traceInfo = new TraceInfoBuilder<TIdentity>(systemName, traceFrame, null)
					.CorrelationId(Guid.NewGuid())
					.ExternalCorrelationId(Guid.NewGuid().ToString("D"))
					.Build();
			}
			else
			{
				traceInfo = new TraceInfoBuilder<TIdentity>(systemName, traceFrame, null)
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
				cookieDataProtectionPurposes: AuthenticationService<TIdentity>.GetDataProtectors(httpContext));
			var appCtx = new ApplicationContext<TIdentity>(traceInfo, appResources, requsetMetadata);
			return appCtx;
		});

	public static IServiceCollection AddEnvelopeAuthentication<TAuthMngr, TCookieStore, TIdentity>(this IServiceCollection services, Action<AuthenticationOptions<TIdentity>>? configureAuthenticationOptions)
		where TAuthMngr : class, IAuthenticationManager<TIdentity>
		where TCookieStore : class, ICookieStore<TIdentity>
		where TIdentity : struct
	{
		services.TryAddSingleton<ICookieStore<TIdentity>, TCookieStore>();
		return AddEnvelopeAuthentication<TAuthMngr, TIdentity>(services, configureAuthenticationOptions, null);
	}

	public static IServiceCollection AddEnvelopeAuthentication<TAuthMngr, TIdentity>(this IServiceCollection services, Action<AuthenticationOptions<TIdentity>>? configureAuthenticationOptions, ICookieStore<TIdentity>? cookieStore = null)
		where TAuthMngr : class, IAuthenticationManager<TIdentity>
		where TIdentity : struct
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

		authenticationBuilder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<AuthenticationOptions<TIdentity>>, PostConfigureAuthenticationOptions<TIdentity>>());
		authenticationBuilder.AddScheme<AuthenticationOptions<TIdentity>, EnvelopeAuthenticationHandler<TIdentity>>(
			AuthenticationDefaults.AuthenticationScheme,
			displayName: null,
			configureOptions: configureAuthenticationOptions);

		services.AddScoped<IAuthenticationManager<TIdentity>, TAuthMngr>();
		services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler<TIdentity>>();

		services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
		services.AddScoped(sp => (sp.GetRequiredService<IHttpContextAccessor>().HttpContext?.User as EnvelopePrincipal<TIdentity>) ?? new EnvelopePrincipal<TIdentity>());

		if (cookieStore != null)
			services.TryAddSingleton(cookieStore);

		return services;
	}

	public static IServiceCollection ConfigureEnvelopeMiddlewares<TAuth, TIdentity>(
		this IServiceCollection services,
		string systemName,
		Action<RequestInitializationOptions<TIdentity>>? configureRequestInitializationOptions = null,
		Action<ForwardedHeadersOptions>? configureForwardedHeadersOptions = null,
		Action<ExceptionHandlerOptions>? configureExceptionHandlerOptions = null,
		Action<HostNormalizerOptions>? configureHostNormalizerOptions = null,
		Action<RequestTrackingOptions>? configureRequestTracking = null,
		Action<AuthenticationOptions<TIdentity>>? configureAuthenticationOptions = null)
		where TAuth : class, IAuthenticationManager<TIdentity>
		where TIdentity : struct
	{
		AddApplicationContext<TIdentity>(services, systemName);

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
			AddEnvelopeAuthentication<TAuth, TIdentity>(services, configureAuthenticationOptions, null);

		return services;
	}
}
