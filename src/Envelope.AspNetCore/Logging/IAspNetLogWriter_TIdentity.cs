using Envelope.AspNetCore.Logging.Dto;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging;

public interface IAspNetLogWriter<TIdentity> : IDisposable
	where TIdentity : struct
{
	void WriteRequest(RequestDto request);
	void WriteRequestAuthentication(RequestAuthentication<TIdentity> requestAuthentication);
	void WriteResponse(ResponseDto response);
}
