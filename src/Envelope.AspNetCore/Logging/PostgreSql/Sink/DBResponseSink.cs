using Envelope.Database.PostgreSql;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

/*
 USAGE:
	Serilog.LoggerConfiguration
		.MinimumLevel.Verbose()
		.WriteTo.DBResponseSink(new Envelope.Logging.DB.SerilogEx.Sink.DBResponseSinkOptions
		{
			ConnectionString = "Host=localhost;Database=..."
		})
		.WriteTo.Console())
 */

public class DBResponseSink : DbBatchWriter<LogEvent>, ILogEventSink, IDisposable
{
	public DBResponseSink(DBResponseSinkOptions options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBResponseSinkOptions(), errorLogger ?? SelfLog.WriteLine)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(LogEvent logEvent)
		=> LogEventHelper.ConvertResponseToDictionary(logEvent);

	public void Emit(LogEvent logEvent)
		=> Write(logEvent);
}
