using Envelope.AspNetCore.Logging.PostgreSql.Sink;

namespace Envelope.AspNetCore.Logging;

public class AspNetLogWriterConfiguration<TIdentity>
	where TIdentity : struct
{
	private RequestWriter? _requestWriter;
	private RequestAuthenticationWriter<TIdentity>? _requestAuthenticationWriter;
	private ResponseWriter? _responseWriter;

	public AspNetLogWriterConfiguration<TIdentity> SetRequestWriter(DBRequestSinkOptions options)
	{
		_requestWriter = new RequestWriter(options);
		return this;
	}

	public AspNetLogWriterConfiguration<TIdentity> SetRequestAuthenticationWriter(DBRequestAuthenticationSinkOptions<TIdentity> options)
	{
		_requestAuthenticationWriter = new RequestAuthenticationWriter<TIdentity>(options);
		return this;
	}

	public AspNetLogWriterConfiguration<TIdentity> SetResponseWriter(DBResponseSinkOptions options)
	{
		_responseWriter = new ResponseWriter(options);
		return this;
	}

	public AspNetLogWriter<TIdentity>? CreateAspNetLogWriter()
	{
		if (_requestWriter == null && _requestAuthenticationWriter == null && _responseWriter == null)
			return null;

		return new AspNetLogWriter<TIdentity>(_requestWriter, _requestAuthenticationWriter, _responseWriter);
	}
}
