using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Envelope.AspNetCore.Middleware.Authentication.RequestAuth.Events;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

#nullable disable

namespace Envelope.AspNetCore.Middleware.Authentication.Events;

public class AuthenticationEvents<TIdentity>
	where TIdentity : struct
{
	public WindowsAuthenticationEvents WindowsEvents { get; }
	public CookieAuthenticationEvents CookieEvents { get; }
	public JwtBearerEvents TokenEvents { get; }
	public RequestAuthenticationEvents RequestEvents { get; }

	public AuthenticationEvents(HttpContext context, AuthenticationOptions<TIdentity> options)
	{
		if (options.UseWindowsAuthentication)
		{
			WindowsEvents = options.WindowsAuthenticationOptions.Events;
			if (options.WindowsAuthenticationOptions.EventsType != null)
			{
				WindowsEvents = (WindowsAuthenticationEvents)context.RequestServices.GetRequiredService(options.WindowsAuthenticationOptions.EventsType);
			}
			WindowsEvents ??= new WindowsAuthenticationEvents();
		}

		if (options.UseCookieAuthentication)
		{
			CookieEvents = options.CookieAuthenticationOptions.Events;
			if (options.CookieAuthenticationOptions.EventsType != null)
			{
				CookieEvents = (CookieAuthenticationEvents)context.RequestServices.GetRequiredService(options.CookieAuthenticationOptions.EventsType);
			}
			CookieEvents ??= new CookieAuthenticationEvents();
		}

		if (options.UseTokenAuthentication)
		{
			TokenEvents = options.TokenAuthenticationOptions.Events;
			if (options.TokenAuthenticationOptions.EventsType != null)
			{
				TokenEvents = (JwtBearerEvents)context.RequestServices.GetRequiredService(options.TokenAuthenticationOptions.EventsType);
			}
			TokenEvents ??= new JwtBearerEvents();
		}

		if (options.UseRequestAuthentication)
		{
			RequestEvents = options.RequestAuthenticationOptions.Events;
			if (options.RequestAuthenticationOptions.EventsType != null)
			{
				RequestEvents = (RequestAuthenticationEvents)context.RequestServices.GetRequiredService(options.RequestAuthenticationOptions.EventsType);
			}
			RequestEvents ??= new RequestAuthenticationEvents();
		}
	}
    }
