using Microsoft.AspNetCore.Mvc;

namespace Envelope.AspNetCore.Middleware.Authentication.Authenticate;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public abstract class AuthenticateAttribute<TIdentity> : TypeFilterAttribute
	where TIdentity : struct
{
	public AuthenticateAttribute()
		: base(typeof(AuthenticateAuthorizationFilter<TIdentity>))
	{
		AddArgument(new AuthenticateAuthorizationRequirement());
		Order = Int32.MinValue;
	}

	protected void AddArgument(object value)
	{
		if (value == null)
		{
			throw new ArgumentNullException(nameof(value));
		}

		var args = new List<object>(base.Arguments ?? Array.Empty<object>())
		{
			value
		};

		base.Arguments = args.ToArray();
	}
}
