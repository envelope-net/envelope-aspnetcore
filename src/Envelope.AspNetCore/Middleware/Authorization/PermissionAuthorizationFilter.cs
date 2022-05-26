using Envelope.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Envelope.AspNetCore.Middleware.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class PermissionAuthorizationFilter<TIdentity> : Attribute, IAsyncAuthorizationFilter, IAsyncActionFilter
	where TIdentity : struct
{
	private readonly IAuthorizationService _authService;
	private readonly PermissionAuthorizationRequirement _requirement;

	public PermissionAuthorizationFilter(IAuthorizationService authService, PermissionAuthorizationRequirement requirement)
	{
		_authService = authService;
		_requirement = requirement;
	}

	public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
	{
		var controllerActionDescriptor = (ControllerActionDescriptor)context.ActionDescriptor;
		var premission = _requirement?.Tokens?.Select(x => x.ToString()).ToList();

		if (premission != null && 0 < premission.Count)
			context.HttpContext.Items[Envelope.AspNetCore.Defaults.Keys.Premission] = premission;

		await next().ConfigureAwait(false);
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
