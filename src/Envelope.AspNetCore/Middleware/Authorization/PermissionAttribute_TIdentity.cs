using Microsoft.AspNetCore.Mvc;

namespace Envelope.AspNetCore.Middleware.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public abstract class PermissionAttribute<TIdentity> : TypeFilterAttribute
	where TIdentity : struct
{
	protected PermissionAttribute()
		: base(typeof(PermissionAuthorizationFilter<TIdentity>))
	{
	}

	public PermissionAttribute(object[] tokens)
		: base(typeof(PermissionAuthorizationFilter<TIdentity>))
	{
		AddArgument(new PermissionAuthorizationRequirement(tokens));
		Order = int.MinValue;
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
