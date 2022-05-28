using Microsoft.Extensions.Options;
using Envelope.Extensions;
using Envelope.Logging.Extensions;
using Envelope.Trace;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace Envelope.AspNetCore.Middleware.HostNormalizer;

public class HostNormalizerMiddleware<TIdentity>
	where TIdentity : struct
{
	private readonly RequestDelegate _next;
	private readonly HostNormalizerOptions _options;
	private readonly ILogger _logger;

	public HostNormalizerMiddleware(
		RequestDelegate next,
		IOptions<HostNormalizerOptions> options,
		ILogger<HostNormalizerMiddleware<TIdentity>> logger)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
		_options = options?.Value ?? throw new ArgumentNullException(nameof(options));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	public async Task InvokeAsync(HttpContext context)
	{
		var ac = context.RequestServices.GetRequiredService<IApplicationContext<TIdentity>>();
		var traceInfo = ac.AddTraceFrame(TraceFrame.Create());

		try
		{
			var request = context.Request;

			string? host = null;
			string? protocol = null;

			if (string.IsNullOrWhiteSpace(_options.Host))
			{
				var forwardedHost = request.Headers["X-Forwarded-Host"];
				if (!string.IsNullOrWhiteSpace(forwardedHost))
					host = forwardedHost;
			}
			else
				host = _options.Host;

			if (string.IsNullOrWhiteSpace(_options.Protocol))
			{
				var forwardedProtocol = request.Headers["X-Forwarded-Proto"];
				if (!string.IsNullOrWhiteSpace(forwardedProtocol))
					protocol = forwardedProtocol;
			}
			else
				protocol = _options.Protocol;

			if (!string.IsNullOrWhiteSpace(host))
				request.Host = new HostString(host);

			if (!string.IsNullOrWhiteSpace(protocol))
				request.Scheme = protocol;

			if (!string.IsNullOrWhiteSpace(_options.VirtualPath))
				request.PathBase = $"/{_options.VirtualPath.TrimPrefix("/")}";
		}
		catch (Exception ex)
		{
			_logger.LogErrorMessage(traceInfo, x => x.ExceptionInfo(ex), true);
		}

		await _next(context).ConfigureAwait(false);
	}
}
