using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Envelope.Identity;

namespace Envelope.AspNetCore.Middleware.Authentication.Authenticate;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class AuthenticateAuthorizationFilter<TIdentity> : Attribute, IAsyncAuthorizationFilter
	where TIdentity : struct
{
	private readonly IAuthorizationService _authService;
	private readonly AuthenticateAuthorizationRequirement _requirement;

	public AuthenticateAuthorizationFilter(IAuthorizationService authService, AuthenticateAuthorizationRequirement requirement)
	{
		_authService = authService;
		_requirement = requirement;
	}

	public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
	{
		if (context.HttpContext.User is EnvelopePrincipal<TIdentity> principal)
		{
			AuthorizationResult result = await _authService.AuthorizeAsync(principal, null!, _requirement).ConfigureAwait(false);

			if (!result.Succeeded)
			{
				context.Result = new ForbidResult(Authentication.AuthenticationDefaults.AuthenticationScheme);
				//context.HttpContext.ThrowAccessDenied403Forbidden();
			}
		}
		else
		{
			context.Result = new ChallengeResult(Authentication.AuthenticationDefaults.AuthenticationScheme);
		}
	}
}
