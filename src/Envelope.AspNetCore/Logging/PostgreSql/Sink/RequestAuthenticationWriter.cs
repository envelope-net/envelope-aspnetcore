using Envelope.AspNetCore.Logging.Dto;
using Envelope.Database.PostgreSql;
using Envelope.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class RequestAuthenticationWriter<TIdentity> : DbBatchWriter<RequestAuthentication<TIdentity>>, IDisposable
	where TIdentity : struct
{
	public RequestAuthenticationWriter(DBRequestAuthenticationSinkOptions<TIdentity> options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBRequestAuthenticationSinkOptions<TIdentity>(), errorLogger ?? DefaultErrorLoggerDelegate.Log)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(RequestAuthentication<TIdentity> requestAuthentication)
		=> requestAuthentication.ToDictionary();
}
