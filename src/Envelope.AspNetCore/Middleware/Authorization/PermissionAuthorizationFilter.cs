using Envelope.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Envelope.AspNetCore.Middleware.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public class PermissionAuthorizationFilter : Attribute, IAsyncAuthorizationFilter, IAsyncActionFilter
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
		var premissions = _requirement?.Tokens?.Select(x => x.ToString()).ToList();

		if (premissions != null && 0 < premissions.Count)
			context.HttpContext.Items[Envelope.AspNetCore.Defaults.Keys.AttributePermissions] = premissions;

		await next().ConfigureAwait(false);
	}

	public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
	{
		if (context.HttpContext.User is EnvelopePrincipal principal)
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
