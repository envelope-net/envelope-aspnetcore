using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Envelope.AspNetCore.Middleware.Authentication.Events;

public class WindowsValidatePrincipalContext : ResultContext<WindowsAuthenticationOptions>
{
	public ILogger Logger { get; }

	/// <summary>
	/// Creates a new instance of the context object.
	/// </summary>
	/// <param name="context"></param>
	/// <param name="scheme"></param>
	/// <param name="options"></param>
	/// <param name="logger"></param>
	public WindowsValidatePrincipalContext(HttpContext context, AuthenticationScheme scheme, WindowsAuthenticationOptions options, ILogger logger)
		: base(context, scheme, options)
	{
		Logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	/// <summary>
	/// Called to replace the claims principal. The supplied principal will replace the value of the 
	/// Principal property, which determines the identity of the authenticated request.
	/// </summary>
	/// <param name="principal">The <see cref="ClaimsPrincipal"/> used as the replacement</param>
	public void ReplacePrincipal(ClaimsPrincipal principal) => Principal = principal;

	/// <summary>
	/// Called to reject the incoming principal. This may be done if the application has determined the
	/// account is no longer active, and the request should be treated as if it was anonymous.
	/// </summary>
	public void RejectPrincipal() => Principal = null;
}
