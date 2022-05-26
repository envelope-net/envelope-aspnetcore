using Envelope.Database.PostgreSql;
using Envelope.Logging;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class RequestWriter : DbBatchWriter<RequestDto>, IDisposable
{
	public RequestWriter(DBRequestSinkOptions options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBRequestSinkOptions(), errorLogger ?? DefaultErrorLoggerDelegate.Log)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(RequestDto request)
		=> request.ToDictionary();
}
