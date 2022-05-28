using Envelope.AspNetCore.Logging.Dto;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.Internal;

internal class SilentAspNetLogWriter<TIdentity> : IAspNetLogWriter<TIdentity>, IDisposable
	where TIdentity : struct
{
	public static readonly IAspNetLogWriter<TIdentity> Instance = new SilentAspNetLogWriter<TIdentity>();

	public void WriteRequest(RequestDto request) { }

	public void WriteRequestAuthentication(RequestAuthentication<TIdentity> requestAuthentication) { }

	public void WriteResponse(ResponseDto response) { }

	public void Dispose() { }
}
