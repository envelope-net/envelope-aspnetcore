using Envelope.AspNetCore.Middleware.Authentication.Events;
using Envelope.AspNetCore.Middleware.Authentication.RequestAuth;
using Envelope.AspNetCore.Middleware.Authentication.RequestAuth.Events;
using Envelope.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

#nullable disable

namespace Envelope.AspNetCore.Middleware.Authentication;

public class AuthenticationOptions<TIdentity> : AuthenticationSchemeOptions
	where TIdentity : struct
{
	public static string Scheme => AuthenticationDefaults.AuthenticationScheme;

	public new AuthenticationEvents<TIdentity> Events
	{
		get => (AuthenticationEvents<TIdentity>)base.Events;
		set => base.Events = value;
	}

	private readonly List<AuthenticationType> _authenticationFlow = new();
	public IReadOnlyList<AuthenticationType> AuthenticationFlow { get; private set; }
	public AuthenticationType? AuthenticationFlowFallback { get; private set; }

	public WindowsAuthenticationOptions WindowsAuthenticationOptions { get; private set; }
	public bool UseWindowsAuthentication => WindowsAuthenticationOptions != null;
	public Func<WindowsValidatePrincipalContext, Task> OnValidateWindowsPrincipal { get; private set; }

	//HttpContext context, string authenticationSchemeType, ILogger logger
	public Func<HttpContext, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> CreateWindowsPrincipal { get; private set; }

	public bool DisableCookieAuthenticationChallenge { get; set; }
	public CookieAuthenticationOptions CookieAuthenticationOptions { get; private set; }

	private string _cookieName;
	public string CookieName => _cookieName ??= $"{CookieAuthenticationDefaults.CookiePrefix}{AuthenticationDefaults.AuthenticationScheme}";

	public bool UseCookieAuthentication => CookieAuthenticationOptions != null;
	public Func<CookieValidatePrincipalContext, Task> OnValidateCookiePrincipal { get; private set; }

	//HttpContext context, string userName, string authenticationSchemeType, ILogger logger
	public Func<HttpContext, string, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> RecreateCookiePrincipal { get; private set; }
	public Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> ConvertCookiePrincipal { get; private set; }

	public bool DisableTokenAuthenticationChallenge { get; set; }
	public JwtBearerOptions TokenAuthenticationOptions { get; private set; }
	public bool UseTokenAuthentication => TokenAuthenticationOptions != null;
	public Func<TokenValidatedContext, Task> OnValidateTokenPrincipal { get; private set; }

	//HttpContext context, string userName, string authenticationSchemeType, ILogger logger
	public Func<HttpContext, string, string, ILogger, EnvelopePrincipal<TIdentity>> RecreateTokenPrincipal { get; private set; }
	public Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> ConvertTokenPrincipal { get; private set; }

	public RequestAuthenticationOptions RequestAuthenticationOptions { get; private set; }
	public bool UseRequestAuthentication => RequestAuthenticationOptions != null;
	public Func<RequestValidatePrincipalContext, Task> OnValidateRequestPrincipal { get; private set; }

	//HttpContext context, string authenticationSchemeType, ILogger logger
	public Func<HttpContext, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> CreateRequestPrincipal { get; private set; }

	public AuthenticationOptions<TIdentity> SetWindowsAuthentication(WindowsAuthenticationOptions options, Func<WindowsValidatePrincipalContext, Task> onValidatePrincipal)
	{
		AddAuthentication(AuthenticationType.WindowsIntegrated);
		WindowsAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		OnValidateWindowsPrincipal = onValidatePrincipal ?? throw new ArgumentNullException(nameof(onValidatePrincipal));
		return this;
	}

	public AuthenticationOptions<TIdentity> SetWindowsAuthentication(Func<HttpContext, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> createPrincipal, bool disableWindowsAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.WindowsIntegrated);
		WindowsAuthenticationOptions = new WindowsAuthenticationOptions { DisableAuthenticationChallenge = disableWindowsAuthenticationChallenge };
		CreateWindowsPrincipal = createPrincipal ?? throw new ArgumentNullException(nameof(createPrincipal));
		OnValidateWindowsPrincipal = async context =>
		{
			if (context.HttpContext?.User != null && context.HttpContext.User.Identity != null)
				context.Principal = await CreateWindowsPrincipal(context.HttpContext, context.Scheme.Name, context.Logger).ConfigureAwait(false);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetCookieAuthentication(Func<CookieValidatePrincipalContext, Task> onValidatePrincipal, bool disableCookieAuthenticationChallenge = false)
		=> SetCookieAuthentication(new CookieAuthenticationOptions(), onValidatePrincipal, disableCookieAuthenticationChallenge);

	public AuthenticationOptions<TIdentity> SetCookieAuthenticationReplacePrincipal(Func<HttpContext, string, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> recreatePrincipal, bool disableCookieAuthenticationChallenge = false)
		=> SetCookieAuthenticationReplacePrincipal(new CookieAuthenticationOptions(), recreatePrincipal, disableCookieAuthenticationChallenge);

	public AuthenticationOptions<TIdentity> SetCookieAuthenticationConvertPrincipal(Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> convertPrincipal, bool disableCookieAuthenticationChallenge = false)
		=> SetCookieAuthenticationConvertPrincipal(new CookieAuthenticationOptions(), convertPrincipal, disableCookieAuthenticationChallenge);

	public AuthenticationOptions<TIdentity> SetCookieAuthentication(CookieAuthenticationOptions options, Func<CookieValidatePrincipalContext, Task> onValidatePrincipal, bool disableCookieAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Cookie);
		CookieAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableCookieAuthenticationChallenge = disableCookieAuthenticationChallenge;
		OnValidateCookiePrincipal = onValidatePrincipal ?? throw new ArgumentNullException(nameof(onValidatePrincipal));
		return this;
	}

	public AuthenticationOptions<TIdentity> SetCookieAuthenticationReplacePrincipal(CookieAuthenticationOptions options, Func<HttpContext, string, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> recreatePrincipal, bool disableCookieAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Cookie);
		CookieAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableCookieAuthenticationChallenge = disableCookieAuthenticationChallenge;
		RecreateCookiePrincipal = recreatePrincipal ?? throw new ArgumentNullException(nameof(recreatePrincipal));
		OnValidateCookiePrincipal = async context =>
		{
			if (context.Principal != null && context.Principal.Identity != null)
				context.Principal = await RecreateCookiePrincipal(context.HttpContext, context.Principal?.Identity?.Name, context.Scheme.Name, null).ConfigureAwait(false);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetCookieAuthenticationConvertPrincipal(CookieAuthenticationOptions options, Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> convertPrincipal, bool disableCookieAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Cookie);
		CookieAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableCookieAuthenticationChallenge = disableCookieAuthenticationChallenge;
		ConvertCookiePrincipal = convertPrincipal ?? throw new ArgumentNullException(nameof(convertPrincipal));
		OnValidateCookiePrincipal = context =>
		{
			if (context.Principal != null && context.Principal.Identity != null)
				context.Principal = ConvertCookiePrincipal(context.Principal);

			return Task.FromResult(0);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetCookieName(string cookieName)
	{
		_cookieName = cookieName;
		return this;
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthentication(TokenValidationParameters tokenValidationParameters, Func<TokenValidatedContext, Task> onValidatePrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		return SetTokenAuthentication(
			new JwtBearerOptions
			{
				TokenValidationParameters = tokenValidationParameters
			},
			onValidatePrincipal,
			disableTokenAuthenticationChallenge);
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthenticationReplacePrincipal(TokenValidationParameters tokenValidationParameters, Func<HttpContext, string, string, ILogger, EnvelopePrincipal<TIdentity>> recreatePrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		return SetTokenAuthenticationReplacePrincipal(
			new JwtBearerOptions
			{
				TokenValidationParameters = tokenValidationParameters
			},
			recreatePrincipal,
			disableTokenAuthenticationChallenge);
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthenticationConvertPrincipal(TokenValidationParameters tokenValidationParameters, Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> convertPrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		return SetTokenAuthenticationConvertPrincipal(
			new JwtBearerOptions
			{
				TokenValidationParameters = tokenValidationParameters
			},
			convertPrincipal,
			disableTokenAuthenticationChallenge);
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthentication(JwtBearerOptions options, Func<TokenValidatedContext, Task> onValidatePrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Token);
		TokenAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableTokenAuthenticationChallenge = disableTokenAuthenticationChallenge;
		OnValidateTokenPrincipal = onValidatePrincipal ?? throw new ArgumentNullException(nameof(onValidatePrincipal));
		return this;
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthenticationReplacePrincipal(JwtBearerOptions options, Func<HttpContext, string, string, ILogger, EnvelopePrincipal<TIdentity>> recreatePrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Token);
		TokenAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableTokenAuthenticationChallenge = disableTokenAuthenticationChallenge;
		RecreateTokenPrincipal = recreatePrincipal ?? throw new ArgumentNullException(nameof(recreatePrincipal));
		OnValidateTokenPrincipal = context =>
		{
			if (context.Principal != null && context.Principal.Identity != null)
				context.Principal = RecreateTokenPrincipal(context.HttpContext, context.Principal?.Identity?.Name, context.Scheme.Name, null);

			return Task.FromResult(0);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetTokenAuthenticationConvertPrincipal(JwtBearerOptions options, Func<ClaimsPrincipal, EnvelopePrincipal<TIdentity>> convertPrincipal, bool disableTokenAuthenticationChallenge = false)
	{
		AddAuthentication(AuthenticationType.Token);
		TokenAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		DisableTokenAuthenticationChallenge = disableTokenAuthenticationChallenge;
		ConvertTokenPrincipal = convertPrincipal ?? throw new ArgumentNullException(nameof(convertPrincipal));
		OnValidateTokenPrincipal = context =>
		{
			if (context.Principal != null && context.Principal.Identity != null)
				context.Principal = ConvertTokenPrincipal(context.Principal);

			return Task.FromResult(0);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetRequestAuthentication(RequestAuthenticationOptions options, Func<RequestValidatePrincipalContext, Task> onValidatePrincipal)
	{
		AddAuthentication(AuthenticationType.Request);
		RequestAuthenticationOptions = options ?? throw new ArgumentNullException(nameof(options));
		OnValidateRequestPrincipal = onValidatePrincipal ?? throw new ArgumentNullException(nameof(onValidatePrincipal));
		return this;
	}

	public AuthenticationOptions<TIdentity> SetRequestAuthentication(Func<HttpContext, string, ILogger, Task<EnvelopePrincipal<TIdentity>>> createPrincipal, bool disableRequestAuthenticationChallenge = false, List<string> anonymousUrlPathPrefixes = null)
	{
		AddAuthentication(AuthenticationType.Request);
		RequestAuthenticationOptions = new RequestAuthenticationOptions { DisableAuthenticationChallenge = disableRequestAuthenticationChallenge, AnonymousUrlPathPrefixes = anonymousUrlPathPrefixes?.Select(x => x.ToLowerInvariant()).ToList() };
		CreateRequestPrincipal = createPrincipal ?? throw new ArgumentNullException(nameof(createPrincipal));
		OnValidateRequestPrincipal = async context =>
		{
			if (context.HttpContext?.User != null && context.HttpContext.User.Identity != null)
				context.Principal = await CreateRequestPrincipal(context.HttpContext, context.Scheme.Name, context.Logger).ConfigureAwait(false);
		};

		return this;
	}

	public AuthenticationOptions<TIdentity> SetAuthenticationFlowFallback(AuthenticationType fallback)
	{
		AuthenticationFlowFallback = fallback;
		return this;
	}

	public override void Validate()
	{
		WindowsAuthenticationOptions?.Validate();
		CookieAuthenticationOptions?.Validate();
		TokenAuthenticationOptions?.Validate();
		RequestAuthenticationOptions?.Validate();
	}

	private void AddAuthentication(AuthenticationType authenticationType)
	{
		if (_authenticationFlow.Contains(authenticationType))
			throw new InvalidOperationException($"{authenticationType} authentication is already set.");

		_authenticationFlow.Add(authenticationType);
	}

	internal void SetAuthenticationFlow()
	{
		if (AuthenticationFlow != null)
			throw new InvalidOperationException($"{AuthenticationFlow} is already set.");

		AuthenticationFlow = _authenticationFlow;
	}
}
