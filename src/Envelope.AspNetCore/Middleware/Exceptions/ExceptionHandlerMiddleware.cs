using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Envelope.Extensions;
using Envelope.Logging.Extensions;
using Envelope.Trace;
using System.Runtime.ExceptionServices;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace Envelope.AspNetCore.Middleware.Exceptions;

public class ExceptionHandlerMiddleware
{
	private readonly RequestDelegate _next;
	private readonly ExceptionHandlerOptions _options;
	private readonly ILogger _logger;
	private readonly Func<object, Task> _clearCacheHeadersDelegate;

	public ExceptionHandlerMiddleware(
		RequestDelegate next,
		IOptions<ExceptionHandlerOptions> options,
		ILogger<ExceptionHandlerMiddleware> logger)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
		_options = options?.Value ?? throw new ArgumentNullException(nameof(options));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_clearCacheHeadersDelegate = ClearCacheHeadersAsync;
		if (_options.ExternalExceptionHandler == null)
		{
			if (_options.DefaultExceptionPath == null)
				throw new InvalidOperationException("An error occurred when configuring the exception handler middleware. Either the 'DefaultExceptionPath' or the 'ExceptionHandler' property must be set.");
		}
	}

	public Task InvokeAsync(HttpContext context)
	{
		ExceptionDispatchInfo? edi = null;
		var appCtx = context.RequestServices.GetRequiredService<IApplicationContext>();
		var traceInfo = appCtx.AddTraceFrame(TraceFrame.Create());
		
		try
		{
			var task = _next(context);
			if (!task.IsCompletedSuccessfully)
			{
				return Awaited(this, traceInfo, context, task, _options);
			}

			if (!_options.CheckEveryResponseStatusCode && context.Response.StatusCode != StatusCodes.Status404NotFound)
				return Task.CompletedTask;
		}
		catch (Exception ex)
		{
			edi = ExceptionDispatchInfo.Capture(ex);
		}

		if (HandleStatusCode(context.Response.StatusCode, _options))
			return HandleExceptionAsync(traceInfo, context, edi);

		return Task.CompletedTask;

		static async Task Awaited(ExceptionHandlerMiddleware middleware, ITraceInfo traceInfo, HttpContext context, Task task, ExceptionHandlerOptions options)
		{
			ExceptionDispatchInfo? edi = null;
			try
			{
				await task.ConfigureAwait(false);
			}
			catch (Exception exception)
			{
				edi = ExceptionDispatchInfo.Capture(exception);
			}

			if (edi != null || HandleStatusCode(context.Response.StatusCode, options))
				await middleware.HandleExceptionAsync(traceInfo, context, edi).ConfigureAwait(false);
		}
	}

	private static bool HandleStatusCode(int statusCode, ExceptionHandlerOptions options)
		=> (options.HandleAllClientAndServerErrors && 400 <= statusCode)
		|| (options.HandleOnlyStatusCodes != null
			&& options.HandleOnlyStatusCodes.Contains(statusCode));

	private async Task HandleExceptionAsync(ITraceInfo traceInfo, HttpContext context, ExceptionDispatchInfo? edi)
	{
		var statusCode = context.Response.StatusCode;
		var ex = edi?.SourceException;
		var error = _logger.LogErrorMessage(traceInfo, x => x.ExceptionInfo(ex).Detail($"StatusCode = {statusCode}"), true);

		if (ex != null)
			ex.AppendLogMessage(error);

		if (_options.OnErrorOccurs != null)
		{
			try
			{
				_options.OnErrorOccurs.Invoke(error, context);
			}
			catch (Exception onErroreEx)
			{
				_logger.LogErrorMessage(traceInfo, x => x.ExceptionInfo(onErroreEx).Detail(nameof(_options.OnErrorOccurs)), true);
			}
		}

		if (context.Response.HasStarted)
		{
			_logger.LogErrorMessage(traceInfo, x => x.InternalMessage("The response has already started, the error handler will not be executed."), true);
			edi?.Throw();
			
			return; //if not thrown
		}

		if (_options.Mode == ExceptionHandlerMode.CatchOnly)
		{
			if (_options.ExternalExceptionHandler != null)
			{
				await _options.ExternalExceptionHandler(context, ex).ConfigureAwait(false);
			}
			else
			{
				edi?.Throw(); // Re-throw the original if we couldn't handle it
			}

			return;
		}

		PathString originalPath = context.Request.Path;
		if (statusCode == StatusCodes.Status404NotFound)
		{
			if (string.IsNullOrWhiteSpace(_options.NotFoundExceptionPath))
			{
				if (!string.IsNullOrWhiteSpace(_options.DefaultExceptionPath))
					context.Request.Path = _options.DefaultExceptionPath;
			}
			else
			{
				context.Request.Path = _options.NotFoundExceptionPath;
			}
		}
		else
		{
			if (!string.IsNullOrWhiteSpace(_options.DefaultExceptionPath))
				context.Request.Path = _options.DefaultExceptionPath;
		}

		try
		{
			ClearHttpContext(context);

			if (ex != null && !string.IsNullOrWhiteSpace(originalPath.Value))
			{
				var exceptionHandlerFeature = new ExceptionHandlerFeature()
				{
					Error = ex,
					Path = originalPath.Value,
				};
				context.Features.Set<IExceptionHandlerFeature>(exceptionHandlerFeature);
				context.Features.Set<IExceptionHandlerPathFeature>(exceptionHandlerFeature);
			}

			if (statusCode != StatusCodes.Status401Unauthorized
				&& statusCode != StatusCodes.Status403Forbidden
				&& statusCode != StatusCodes.Status404NotFound)
			{
				statusCode = StatusCodes.Status500InternalServerError;
			}

			context.Response.StatusCode = statusCode;
			context.Response.OnStarting(_clearCacheHeadersDelegate, context.Response);

			await _next(context).ConfigureAwait(false);

			return;
		}
		catch (Exception ex2)
		{
			_logger.LogErrorMessage(traceInfo, x => x.ExceptionInfo(ex2).Detail("An exception was thrown attempting to execute the error handler."), true);
		}
		finally
		{
			context.Request.Path = originalPath;
		}

		edi?.Throw(); // Re-throw the original if we couldn't handle it
	}

	private static void ClearHttpContext(HttpContext context)
	{
		context.Response.Clear();

		context.SetEndpoint(endpoint: null);
		var routeValuesFeature = context.Features.Get<IRouteValuesFeature>();
		routeValuesFeature?.RouteValues?.Clear();
	}

	private static Task ClearCacheHeadersAsync(object state)
	{
		var headers = ((HttpResponse)state).Headers;
		headers[HeaderNames.CacheControl] = "no-cache,no-store";
		headers[HeaderNames.Pragma] = "no-cache";
		headers[HeaderNames.Expires] = "-1";
		headers.Remove(HeaderNames.ETag);
		return Task.CompletedTask;
	}
}
