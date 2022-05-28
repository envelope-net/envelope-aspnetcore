using Envelope.AspNetCore.Logging.PostgreSql.Sink;

namespace Envelope.AspNetCore.Logging;

public class AspNetLogWriterConfiguration
{
	private RequestWriter? _requestWriter;
	private RequestAuthenticationWriter? _requestAuthenticationWriter;
	private ResponseWriter? _responseWriter;

	public AspNetLogWriterConfiguration SetRequestWriter(DBRequestSinkOptions options)
	{
		_requestWriter = new RequestWriter(options);
		return this;
	}

	public AspNetLogWriterConfiguration SetRequestAuthenticationWriter(DBRequestAuthenticationSinkOptions options)
	{
		_requestAuthenticationWriter = new RequestAuthenticationWriter(options);
		return this;
	}

	public AspNetLogWriterConfiguration SetResponseWriter(DBResponseSinkOptions options)
	{
		_responseWriter = new ResponseWriter(options);
		return this;
	}

	public AspNetLogWriter? CreateAspNetLogWriter()
	{
		if (_requestWriter == null && _requestAuthenticationWriter == null && _responseWriter == null)
			return null;

		return new AspNetLogWriter(_requestWriter, _requestAuthenticationWriter, _responseWriter);
	}
}
