using Envelope.Database.PostgreSql;
using Envelope.Logging;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class ResponseWriter : DbBatchWriter<ResponseDto>, IDisposable
{
	public ResponseWriter(DBResponseSinkOptions options, Action<string, object?, object?, object?>? errorLogger = null)
		: base(options ?? new DBResponseSinkOptions(), errorLogger ?? DefaultErrorLoggerDelegate.Log)
	{
	}

	public override IDictionary<string, object?>? ToDictionary(ResponseDto response)
		=> response.ToDictionary();
}
