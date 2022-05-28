using Envelope.Logging;
using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Exceptions;

public class ExceptionHandlerOptions<TIdentity>
	where TIdentity : struct
{
	public ExceptionHandlerMode Mode { get; set; } = ExceptionHandlerMode.CatchAndRedirect;
	public string? DefaultExceptionPath { get; set; }
	public string? NotFoundExceptionPath { get; set; }
	public bool HandleAllClientAndServerErrors { get; set; }
	public List<int>? HandleOnlyStatusCodes { get; set; }
	internal Action<IErrorMessage<TIdentity>, HttpContext>? OnErrorOccurs { get; set; } //Action<IErrorMessage, HttpContext>
	public ExceptionHandlerDelegate? ExternalExceptionHandler { get; set; }
	public bool CheckEveryResponseStatusCode { get; set; }

	public ExceptionHandlerOptions<TIdentity> OnError(Action<IErrorMessage<TIdentity>, HttpContext> action)
	{
		OnErrorOccurs = action;
		return this;
	}
}
