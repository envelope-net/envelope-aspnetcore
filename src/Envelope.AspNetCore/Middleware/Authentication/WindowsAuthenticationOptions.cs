using Envelope.AspNetCore.Middleware.Authentication.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Authentication;

public class WindowsAuthenticationOptions : AuthenticationSchemeOptions
{
	public bool AllowStaticLogin { get; set; }
	public PathString? AccessDeniedPath { get; set; }
	public PathString? UnauthorizedPath { get; set; }
	public string? ReturnUrlParameter { get; set; }
	public bool DisableAuthenticationChallenge { get; set; }

	public new WindowsAuthenticationEvents? Events
	{
		get => (WindowsAuthenticationEvents?)base.Events;
		set => base.Events = value;
	}
}
