using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Exceptions;

/// <summary>
/// A function that can process an HTTP request.
/// </summary>
/// <param name="context">The <see cref="HttpContext"/> for the request.</param>
/// <param name="exception">The <see cref="Exception"/> occured.</param>
/// <returns>A task that represents the completion of request processing.</returns>
public delegate Task ExceptionHandlerDelegate(HttpContext context, Exception? exception);
