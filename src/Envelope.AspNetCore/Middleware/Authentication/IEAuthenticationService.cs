using Envelope.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;

namespace Envelope.AspNetCore.Middleware.Authentication;

public interface IEAuthenticationService
{
	Task<EnvelopePrincipal> AuthenticateAsync(
		AuthenticationScheme scheme,
		IAuthenticationHandler authenticationHandler,
		IServiceProvider scopeServiceProvider,
		HttpContext context,
		EAuthenticationOptions options,
		ILogger logger,
		UrlEncoder urlEncoder,
		ISystemClock clock);
}
