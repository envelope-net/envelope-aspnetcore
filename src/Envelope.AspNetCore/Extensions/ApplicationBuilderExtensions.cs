﻿using Envelope.AspNetCore.Middleware.Exceptions;
using Envelope.AspNetCore.Middleware.HostNormalizer;
using Envelope.AspNetCore.Middleware.Initialization;
using Envelope.AspNetCore.Middleware.Security;
using Envelope.AspNetCore.Middleware.Tracking;
using Envelope.Logging.PostgreSql;
using Microsoft.AspNetCore.Builder;

namespace Envelope.AspNetCore.Extensions;

public static partial class ApplicationBuilderExtensions
{
	public static IApplicationBuilder UseEnvelopeAspNetCore(this IApplicationBuilder app, string applicationName)
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		//var loggerFactory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
		//var logger = loggerFactory.CreateLogger<RequestInitializationMiddleware>();
		//logger.LogEnvironmentInfo();

		DbLogWriter.Instance.WriteEnvironmentInfo(applicationName);

		app.UseMiddleware<RequestInitializationMiddleware>();

		return app;
	}

	public static IApplicationBuilder UseEnvelopeExceptionHandler(this IApplicationBuilder app)
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<ExceptionHandlerMiddleware>();
		return app;
	}

	public static IApplicationBuilder UseEnvelopeHostNormalizer(this IApplicationBuilder app)
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<HostNormalizerMiddleware>();
		return app;
	}

	public static IApplicationBuilder UseEnvelopeRequestTracking(this IApplicationBuilder app)
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<RequestTrackingMiddleware>();
		return app;
	}

	public static IApplicationBuilder UseEnvelopeHeadersSecurity(this IApplicationBuilder app)
	{
		if (app == null)
			throw new ArgumentNullException(nameof(app));

		app.UseMiddleware<SecurityMiddleware>();
		return app;
	}

	///// <summary>
	///// 0. UseEnvelopeAspNetCore
	///// 1. RequestInitializationMiddleware
	///// 2. UseForwardedHeaders
	///// 3. UseStaticFiles
	///// 4. ExceptionHandlerMiddleware
	///// 5. HostNormalizerMiddleware
	///// 6. RequestTrackingMiddleware
	///// 7. UseAuthentication
	///// </summary>
	///// <returns></returns>
	//public static IApplicationBuilder UseEnvelopeAspNetCore(
	//	this IApplicationBuilder app,
	//	bool useForwardedHeaders,
	//	ForwardedHeadersOptions forwardedHeadersOptions,
	//	bool useStaticFiles,
	//	StaticFileOptions staticFileOptions,
	//	bool useHostNormalizer)
	//{
	//	app.UseEnvelopeAspNetCore();

	//	if (useForwardedHeaders)
	//	{
	//		if (forwardedHeadersOptions == null)
	//			app.UseForwardedHeaders();
	//		else
	//			app.UseForwardedHeaders(forwardedHeadersOptions);
	//	}

	//	if (useStaticFiles)
	//	{
	//		if (staticFileOptions == null)
	//			app.UseStaticFiles();
	//		else
	//			app.UseStaticFiles(staticFileOptions);
	//	}

	//	app.UseEnvelopeExceptionHandler();

	//	if (useHostNormalizer)
	//		app.UseEnvelopeHostNormalizer();

	//	app.UseEnvelopeRequestTracking();

	//	app.UseAuthentication();

	//	return app;
	//}
}
