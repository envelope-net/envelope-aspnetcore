using Serilog.Events;

namespace Envelope.AspNetCore.Logging;

public static class LogEventHelper
{
	public static bool IsRequest(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.IsLogType(LoggerSettings.Request, logEvent);

	public static IDictionary<string, object?>? ConvertRequestToDictionary(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.ConvertToDictionary(LoggerSettings.Request, logEvent);

	public static bool IsResponse(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.IsLogType(LoggerSettings.Response, logEvent);

	public static IDictionary<string, object?>? ConvertResponseToDictionary(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.ConvertToDictionary(LoggerSettings.Response, logEvent);

	public static bool IsRequestAuthentication(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.IsLogType(LoggerSettings.RequestAuthentication, logEvent);

	public static IDictionary<string, object?>? ConvertRequestAuthenticationToDictionary(LogEvent logEvent)
		=> Envelope.Logging.SerilogEx.LogEventHelper.ConvertToDictionary(LoggerSettings.RequestAuthentication, logEvent);
}
