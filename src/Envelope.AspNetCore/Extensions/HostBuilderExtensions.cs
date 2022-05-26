using Envelope.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Logging.EventLog;

namespace Envelope.AspNetCore.Extensions;

public static class HostBuilderExtensions
{
	public static IHostBuilder UseEnvelopeLogging(
		this IHostBuilder hostBuilder,
		Serilog.ILogger? logger = null,
		bool dispose = false,
		bool addConsoleLogger = true,
		Action<ConsoleLoggerOptions>? configureConsoleLogger = null,
		bool addDebugLogger = true,
		bool addEventSourceLogger = true,
		bool addEventLogLogger = true,
		Action<EventLogSettings>? configureEventLogLogger = null)
	{
		if (hostBuilder == null)
			throw new ArgumentNullException(nameof(hostBuilder));

		hostBuilder
			.ConfigureLogging(cfg => cfg
			.AddEnvelopeSerilog(logger, dispose, addConsoleLogger, configureConsoleLogger, addDebugLogger, addEventSourceLogger, addEventLogLogger, configureEventLogLogger));

		return hostBuilder;
	}
}
