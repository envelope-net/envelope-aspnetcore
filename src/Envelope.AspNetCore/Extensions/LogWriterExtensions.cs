using Envelope.AspNetCore.Logging;
using Envelope.Logging;

namespace Envelope.AspNetCore.Extensions;

public static class LogWriterExtensions
{
	public static LogWriterConfiguration ConfigureAspNetLogWriter<TIdentity>(
		this LogWriterConfiguration loggerConfiguration,
		Action<AspNetLogWriterConfiguration<TIdentity>> configuration)
		where TIdentity : struct
	{
		if (configuration != null)
		{
			var aspNetLogWriterConfiguration = new AspNetLogWriterConfiguration<TIdentity>();
			configuration.Invoke(aspNetLogWriterConfiguration);
			var writer = aspNetLogWriterConfiguration.CreateAspNetLogWriter();
			if (writer != null)
				AspNetLogWriter<TIdentity>.Instance = writer;
		}

		return loggerConfiguration;
	}
}
