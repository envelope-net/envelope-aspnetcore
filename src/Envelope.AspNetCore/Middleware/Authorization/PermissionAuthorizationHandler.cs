using Envelope.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Envelope.AspNetCore.Middleware.Authorization;

public class PermissionAuthorizationHandler<TIdentity> : AuthorizationHandler<PermissionAuthorizationRequirement>
	where TIdentity : struct
{
	private readonly PermissionAuthorizationOptions _options;

	public PermissionAuthorizationHandler(IOptions<PermissionAuthorizationOptions> options)
	{
		_options = options?.Value ?? new PermissionAuthorizationOptions();
	}

	protected override Task HandleRequirementAsync(
		AuthorizationHandlerContext context,
		PermissionAuthorizationRequirement requirement)
	{
		if (context.User is EnvelopePrincipal<TIdentity> principal)
		{
			var hasPermission = _options.UseIntPermissions
				? principal.HasAnyPermissionClaim(
						requirement
							.Tokens
							.Where(x => x != null)
							.Select(x => (TIdentity)x)
							.ToArray())
				: principal.HasAnyPermissionClaim(
						requirement
							.Tokens
							.Where(x => x != null)
							.Select(x => x.ToString())
							.Cast<string>()
							.ToArray());

			if (hasPermission)
			{
				context.Succeed(requirement);
				if (_options.OnSuccess != null)
				{
					try
					{
						_options.OnSuccess.Invoke(context.User, requirement, this.GetType());
					}
					catch { }
				}
			}
			else if (_options.OnFail != null)
			{
				try
				{
					_options.OnFail.Invoke(context.User, requirement, this.GetType());
				}
				catch { }
			}
		}

		return Task.CompletedTask;
	}
}
