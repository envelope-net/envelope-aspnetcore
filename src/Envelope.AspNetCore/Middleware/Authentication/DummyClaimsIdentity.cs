using Envelope.Identity;
using System.Security.Claims;

#nullable disable

namespace Envelope.AspNetCore.Middleware.Authentication;

public class DummyClaimsIdentity
{
	public Guid Identifier { get; set; }
	public string Name { get; set; }
	public string DisplayName { get; set; }
	public object UserData { get; }

	public DummyClaimsIdentity()
	{

	}

	public EnvelopePrincipal CreateEnvelopePrincipal(string authenticationSchemeType)
	{
		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, Name));

		var identity = new EnvelopeIdentity(
			claimsIdentity,
			Identifier,
			Name,
			DisplayName,
			UserData,
			false,
			new List<string> { "Role1" },
			new List<Guid> { default },
			new List<string>() { "action1" },
			new List<Guid> { default },
			false,
			false);

		return new EnvelopePrincipal(identity);
	}
}
