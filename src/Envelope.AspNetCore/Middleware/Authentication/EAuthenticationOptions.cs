using Microsoft.AspNetCore.Authentication;

namespace Envelope.AspNetCore.Middleware.Authentication;

public class EAuthenticationOptions : AuthenticationSchemeOptions
{
	public Func<IServiceProvider, IEAuthenticationService> AuthenticationServiceFactory { get; set; }
}
