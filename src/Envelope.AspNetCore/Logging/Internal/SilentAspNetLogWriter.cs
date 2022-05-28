using Envelope.AspNetCore.Logging.Dto;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.Internal;

internal class SilentAspNetLogWriter : IAspNetLogWriter, IDisposable
{
	public static readonly IAspNetLogWriter Instance = new SilentAspNetLogWriter();

	public void WriteRequest(RequestDto request) { }

	public void WriteRequestAuthentication(RequestAuthentication requestAuthentication) { }

	public void WriteResponse(ResponseDto response) { }

	public void Dispose() { }
}
