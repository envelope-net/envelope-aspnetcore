using Envelope.AspNetCore.Middleware.Exceptions;
using Envelope.AspNetCore.Middleware.HostNormalizer;
using Envelope.AspNetCore.Middleware.Initialization;
using Envelope.AspNetCore.Middleware.Tracking;
using Envelope.Logging.PostgreSql;
using Microsoft.AspNetCore.Builder;

namespace Envelope.AspNetCore.Extensions;

public static partial class ApplicationBuilderExtensions
{
	public static IApplicationBuilder UseEnvelopeAspNetCore<TIdentity>(this IApplicationBuilder app, string applicationName)
		where TIdentity : struct
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		//var loggerFactory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
		//var logger = loggerFactory.CreateLogger<RequestInitializationMiddleware>();
		//logger.LogEnvironmentInfo();

		DbLogWriter.Instance.WriteEnvironmentInfo(applicationName);

		app.UseMiddleware<RequestInitializationMiddleware<TIdentity>>();

		return app;
	}

	public static IApplicationBuilder UseEnvelopeExceptionHandler<TIdentity>(this IApplicationBuilder app)
		where TIdentity : struct
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<ExceptionHandlerMiddleware<TIdentity>>();
		return app;
	}

	public static IApplicationBuilder UseEnvelopeHostNormalizer<TIdentity>(this IApplicationBuilder app)
		where TIdentity : struct
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<HostNormalizerMiddleware<TIdentity>>();
		return app;
	}

	public static IApplicationBuilder UseEnvelopeRequestTracking<TIdentity>(this IApplicationBuilder app)
		where TIdentity : struct
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<RequestTrackingMiddleware<TIdentity>>();
		return app;
	}
}
