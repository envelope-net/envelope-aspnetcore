using Envelope.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Envelope.AspNetCore.Middleware.Authentication.Authenticate;

public class AuthenticateAuthorizationHandler<TIdentity> : AuthorizationHandler<AuthenticateAuthorizationRequirement>
	where TIdentity : struct
{
	private readonly AuthenticateAuthorizationOptions _options;

	public AuthenticateAuthorizationHandler(IOptions<AuthenticateAuthorizationOptions> options)
	{
		_options = options?.Value ?? throw new ArgumentNullException(nameof(options));
	}

	protected override Task HandleRequirementAsync(
		AuthorizationHandlerContext context,
		AuthenticateAuthorizationRequirement requirement)
	{
		if (context.User is EnvelopePrincipal<TIdentity>)
		{
			context.Succeed(requirement);
			if (_options != null)
			{
				try
				{
					_options.OnSuccess?.Invoke(context.User, requirement, this.GetType());
				}
				catch { }
			}
		}
		else if (_options != null)
		{
			try
			{
				_options.OnFail?.Invoke(context.User, requirement, this.GetType());
			}
			catch { }
		}

		return Task.CompletedTask;
	}
}
