using Envelope.Database.PostgreSql;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

/*
 USAGE:
	Serilog.LoggerConfiguration
		.MinimumLevel.Verbose()
		.WriteTo.DBRequestSink(new Envelope.Logging.DB.SerilogEx.Sink.DBRequestSinkOptions
		{
			ConnectionString = "Host=localhost;Database=..."
		})
		.WriteTo.Console())
 */

public class DBRequestSink : DbBatchWriter<LogEvent>, ILogEventSink, IDisposable
{
	public DBRequestSink(DBRequestSinkOptions options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBRequestSinkOptions(), errorLogger ?? SelfLog.WriteLine)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(LogEvent logEvent)
		=> LogEventHelper.ConvertRequestToDictionary(logEvent);

	public void Emit(LogEvent logEvent)
		=> Write(logEvent);
}
