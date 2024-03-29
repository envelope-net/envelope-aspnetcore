﻿using Envelope.AspNetCore.Logging.Dto;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging;

public interface IAspNetLogWriter : IDisposable
{
	void WriteRequest(RequestDto request);
	void WriteRequestAuthentication(RequestAuthentication requestAuthentication);
	void WriteResponse(ResponseDto response);
}
