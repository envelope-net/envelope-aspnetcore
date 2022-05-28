using Envelope.AspNetCore.Logging.Dto;
using Envelope.Database.PostgreSql;
using Envelope.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class RequestAuthenticationWriter : DbBatchWriter<RequestAuthentication>, IDisposable
{
	public RequestAuthenticationWriter(DBRequestAuthenticationSinkOptions options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBRequestAuthenticationSinkOptions(), errorLogger ?? DefaultErrorLoggerDelegate.Log)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(RequestAuthentication requestAuthentication)
		=> requestAuthentication.ToDictionary();
}
