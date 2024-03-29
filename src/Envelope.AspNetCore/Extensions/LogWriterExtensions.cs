﻿using Envelope.AspNetCore.Logging;
using Envelope.Logging;

namespace Envelope.AspNetCore.Extensions;

public static partial class LogWriterExtensions
{
	public static LogWriterConfiguration ConfigureAspNetLogWriter(
		this LogWriterConfiguration loggerConfiguration,
		Action<AspNetLogWriterConfiguration> configuration)
	{
		if (configuration != null)
		{
			var aspNetLogWriterConfiguration = new AspNetLogWriterConfiguration();
			configuration.Invoke(aspNetLogWriterConfiguration);
			var writer = aspNetLogWriterConfiguration.CreateAspNetLogWriter();
			if (writer != null)
				AspNetLogWriter.Instance = writer;
		}

		return loggerConfiguration;
	}
}
