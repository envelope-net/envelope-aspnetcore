using System.Security.Claims;

namespace Envelope.AspNetCore.Middleware.Authorization;

public class PermissionAuthorizationOptions
{
	public bool UseIntPermissions { get; set; } = true;
	public Action<ClaimsPrincipal, PermissionAuthorizationRequirement, Type>? OnSuccess { get; set; }
	public Action<ClaimsPrincipal, PermissionAuthorizationRequirement, Type>? OnFail { get; set; }

	public PermissionAuthorizationOptions()
	{
	}
}
