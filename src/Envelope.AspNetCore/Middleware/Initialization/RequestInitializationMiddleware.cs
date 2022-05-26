using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Envelope.Extensions;
using Envelope.Logging;
using Envelope.Trace;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace Envelope.AspNetCore.Middleware.Initialization;

public class RequestInitializationMiddleware<TIdentity>
	where TIdentity : struct
{
	private readonly RequestDelegate _next;
	private readonly RequestInitializationOptions<TIdentity> _options;
	private readonly ILogger _logger;

	public RequestInitializationMiddleware(
		RequestDelegate next,
		IOptions<RequestInitializationOptions<TIdentity>> options,
		ILogger<RequestInitializationMiddleware<TIdentity>> logger)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
		_options = options?.Value ?? throw new ArgumentNullException(nameof(options));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	public async Task InvokeAsync(HttpContext context)
	{
		if (_options.UseCorrelationIdFromClient
			&& context.Request.Headers.TryGetValue(_options.Header, out StringValues externalCorrelationId))
		{
			context.TraceIdentifier = externalCorrelationId;
		}

		var appCtx = context.RequestServices.GetRequiredService<IApplicationContext<TIdentity>>();
		appCtx.AddTraceFrame(TraceFrame.Create());

		if (_options.IncludeInResponse)
		{
			context.Response.OnStarting(() =>
			{
				context
					.Response
					.Headers
					.AddUniqueKey(_options.Header, new[] { context.TraceIdentifier });
				return Task.CompletedTask;
			});
		}

		using var disposable = _logger.BeginScope(new Dictionary<string, Guid?>
		{
			[nameof(ILogMessage<TIdentity>.TraceInfo.CorrelationId)] = appCtx.TraceInfo.CorrelationId
		});

		if (_options.OnRequestInitialized != null)
			await _options.OnRequestInitialized(appCtx).ConfigureAwait(false);

		await _next(context).ConfigureAwait(false);
	}
}
