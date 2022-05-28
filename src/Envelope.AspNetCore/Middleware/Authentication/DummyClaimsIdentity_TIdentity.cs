using Envelope.Identity;
using System.Security.Claims;

#nullable disable

namespace Envelope.AspNetCore.Middleware.Authentication;

public class DummyClaimsIdentity<TIdentity>
	where TIdentity : struct
{
	public TIdentity Identifier { get; set; }
	public string Name { get; set; }
	public string DisplayName { get; set; }
	public object UserData { get; }

	public DummyClaimsIdentity()
	{

	}

	public EnvelopePrincipal<TIdentity> CreateEnvelopePrincipal(string authenticationSchemeType)
	{
		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, Name));

		var identity = new EnvelopeIdentity<TIdentity>(
			claimsIdentity,
			Identifier,
			Name,
			DisplayName,
			UserData,
			new List<string> { "Role1" },
			new List<TIdentity> { default },
			new List<string>() { "action1" },
			new List<TIdentity> { default },
			false,
			false);

		return new EnvelopePrincipal<TIdentity>(identity);
	}
}
