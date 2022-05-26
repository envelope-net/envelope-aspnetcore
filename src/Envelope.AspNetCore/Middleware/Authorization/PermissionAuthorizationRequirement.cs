using Microsoft.AspNetCore.Authorization;

namespace Envelope.AspNetCore.Middleware.Authorization;

public class PermissionAuthorizationRequirement : IAuthorizationRequirement
{
	public object[] Tokens { get; set; }

	public PermissionAuthorizationRequirement(object[] tokens)
	{
		Tokens = tokens;
	}
}
