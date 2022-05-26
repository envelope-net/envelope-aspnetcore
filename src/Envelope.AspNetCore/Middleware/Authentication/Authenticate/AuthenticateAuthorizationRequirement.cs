using Microsoft.AspNetCore.Authorization;

namespace Envelope.AspNetCore.Middleware.Authentication.Authenticate;

public class AuthenticateAuthorizationRequirement : IAuthorizationRequirement
{
	public AuthenticateAuthorizationRequirement()
	{
	}
}
