using Envelope.Database.PostgreSql;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

/*
 USAGE:
	Serilog.LoggerConfiguration
		.MinimumLevel.Verbose()
		.WriteTo.DBRequestAuthenticationSink(new Envelope.Logging.DB.SerilogEx.Sink.DBRequestAuthenticationSinkOptions
		{
			ConnectionString = "Host=localhost;Database=..."
		})
		.WriteTo.Console())
 */

public class DBRequestAuthenticationSink<TIdentity> : DbBatchWriter<LogEvent>, ILogEventSink, IDisposable
	where TIdentity : struct
{
	public DBRequestAuthenticationSink(DBRequestAuthenticationSinkOptions<TIdentity> options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBRequestAuthenticationSinkOptions<TIdentity>(), errorLogger ?? SelfLog.WriteLine)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(LogEvent logEvent)
		=> LogEventHelper.ConvertRequestAuthenticationToDictionary(logEvent);

	public void Emit(LogEvent logEvent)
		=> Write(logEvent);
}
