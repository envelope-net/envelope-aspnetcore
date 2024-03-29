﻿using Envelope.Logging;
using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Exceptions;

public enum ExceptionHandlerMode
{
	CatchAndRedirect = 0,
	CatchOnly = 1
}

public class ExceptionHandlerOptions
{
	public ExceptionHandlerMode Mode { get; set; } = ExceptionHandlerMode.CatchAndRedirect;
	public string? DefaultExceptionPath { get; set; }
	public string? NotFoundExceptionPath { get; set; }
	public bool HandleAllClientAndServerErrors { get; set; }
	public List<int>? HandleOnlyStatusCodes { get; set; }
	internal Action<IErrorMessage, HttpContext>? OnErrorOccurs { get; set; } //Action<IErrorMessage, HttpContext>
	public ExceptionHandlerDelegate? ExternalExceptionHandler { get; set; }
	public bool CheckEveryResponseStatusCode { get; set; }

	public ExceptionHandlerOptions OnError(Action<IErrorMessage, HttpContext> action)
	{
		OnErrorOccurs = action;
		return this;
	}
}
