using Envelope.AspNetCore.Logging.Dto;
using Envelope.AspNetCore.Logging.Internal;
using Envelope.AspNetCore.Logging.PostgreSql.Sink;
using Envelope.Extensions;
using Envelope.Logging;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging;

public class AspNetLogWriter<TIdentity> : IAspNetLogWriter<TIdentity>, IDisposable
	where TIdentity : struct
{
	private static IAspNetLogWriter<TIdentity> _instance = SilentAspNetLogWriter<TIdentity>.Instance;

	public static IAspNetLogWriter<TIdentity> Instance
	{
		get => _instance;
		set => _instance = value ?? throw new ArgumentNullException(nameof(value));
	}

	private readonly RequestWriter? _requestWriter;
	private readonly RequestAuthenticationWriter<TIdentity>? _requestAuthenticationWriter;
	private readonly ResponseWriter? _responseWriter;

	internal AspNetLogWriter(
		RequestWriter? requestWriter,
		RequestAuthenticationWriter<TIdentity>? requestAuthenticationWriter,
		ResponseWriter? responseWriter)
	{
		_requestWriter = requestWriter;
		_requestAuthenticationWriter = requestAuthenticationWriter;
		_responseWriter = responseWriter;
	}

	public void WriteRequest(RequestDto request)
	{
		if (request == null)
			return;

		if (_requestWriter == null)
			throw new InvalidOperationException($"{nameof(RequestWriter)} was not configured");

		_requestWriter.Write(request);
	}

	public void WriteRequestAuthentication(RequestAuthentication<TIdentity> requestAuthentication)
	{
		if (requestAuthentication == null)
			return;

		if (_requestAuthenticationWriter == null)
			throw new InvalidOperationException($"{nameof(RequestAuthenticationWriter<TIdentity>)} was not configured");

		_requestAuthenticationWriter.Write(requestAuthentication);
	}

	public void WriteResponse(ResponseDto response)
	{
		if (response == null)
			return;

		if (_responseWriter == null)
			throw new InvalidOperationException($"{nameof(ResponseWriter)} was not configured");

		_responseWriter.Write(response);
	}

	public static void CloseAndFlush()
	{
		var aspNetLogWriter = Interlocked.Exchange(ref _instance, SilentAspNetLogWriter<TIdentity>.Instance);
		aspNetLogWriter?.Dispose();
	}

	private bool disposed;
	protected virtual void Dispose(bool disposing)
	{
		if (!disposed)
		{
			if (disposing)
			{
				try
				{
					_requestWriter?.Dispose();
				}
				catch (Exception ex)
				{
					var msg = string.Format($"{nameof(LogWriter)}: Disposing {nameof(_requestWriter)} '{_requestWriter?.GetType().FullName ?? "null"}': {ex.ToStringTrace()}");
					Serilog.Log.Logger.Error(ex, msg);
				}

				try
				{
					_requestAuthenticationWriter?.Dispose();
				}
				catch (Exception ex)
				{
					var msg = string.Format($"{nameof(LogWriter)}: Disposing {nameof(_requestAuthenticationWriter)} '{_requestAuthenticationWriter?.GetType().FullName ?? "null"}': {ex.ToStringTrace()}");
					Serilog.Log.Logger.Error(ex, msg);
				}

				try
				{
					_responseWriter?.Dispose();
				}
				catch (Exception ex)
				{
					var msg = string.Format($"{nameof(LogWriter)}: Disposing {nameof(_responseWriter)} '{_responseWriter?.GetType().FullName ?? "null"}': {ex.ToStringTrace()}");
					Serilog.Log.Logger.Error(ex, msg);
				}
			}

			disposed = true;
		}
	}

	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}
}
