using Envelope.Identity;
using System.Security.Claims;

namespace Envelope.AspNetCore.Middleware.Authorization;

public delegate bool HasPermissionDelegate(EnvelopePrincipal principal, IEnumerable<Guid> permissions);

public class PermissionAuthorizationOptions
{
	public Action<ClaimsPrincipal, PermissionAuthorizationRequirement, Type>? OnSuccess { get; set; }
	public Action<ClaimsPrincipal, PermissionAuthorizationRequirement, Type>? OnFail { get; set; }
	public HasPermissionDelegate OnHasPermission { get; set; } = DefaultHasPermission;

	public static bool DefaultHasPermission(EnvelopePrincipal principal, IEnumerable<Guid> permissions)
	{
		if (principal == null || permissions?.Any() != true)
			return false;

		return principal.HasAnyPermissionClaim(permissions.ToArray());
	}
}
