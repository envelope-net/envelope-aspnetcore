using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Envelope.AspNetCore.Middleware.Authentication;

public class PostConfigureAuthenticationOptions<TIdentity> : IPostConfigureOptions<AuthenticationOptions<TIdentity>>
	where TIdentity : struct
{
	private readonly IDataProtectionProvider _dp;

	public PostConfigureAuthenticationOptions(IDataProtectionProvider dataProtection)
	{
		_dp = dataProtection;
	}

	public void PostConfigure(string name, AuthenticationOptions<TIdentity> options)
	{
		//if (_options.VirtualPath == null)
		//{
		//    RouteContext routeContext = new RouteContext(context);
		//    VirtualPathContext virtualPathContext = new VirtualPathContext(context, null, routeContext.RouteData.Values);
		//    VirtualPathData virtualPathData = _options.Router.GetVirtualPath(virtualPathContext);
		//    _options.SetVirtualPath(virtualPathData.VirtualPath);
		//}


		if (options.UseWindowsAuthentication)
		{
			if (options.WindowsAuthenticationOptions.Events == null)
				options.WindowsAuthenticationOptions.Events = new Events.WindowsAuthenticationEvents();

			options.WindowsAuthenticationOptions.Events.OnValidatePrincipal = options.OnValidateWindowsPrincipal;
		}

		if (options.UseCookieAuthentication)
		{
			options.CookieAuthenticationOptions.DataProtectionProvider = options.CookieAuthenticationOptions.DataProtectionProvider ?? _dp;

			if (string.IsNullOrEmpty(options.CookieAuthenticationOptions.Cookie.Name))
			{
				options.CookieAuthenticationOptions.Cookie.Name = string.IsNullOrWhiteSpace(options.CookieName)
					? CookieAuthenticationDefaults.CookiePrefix + name
					: options.CookieName;
			}
			if (options.CookieAuthenticationOptions.TicketDataFormat == null)
			{
				// Note: the purpose for the data protector must remain fixed for interop to work.
				var dataProtector = options.CookieAuthenticationOptions.DataProtectionProvider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", name, "v2");
				options.CookieAuthenticationOptions.TicketDataFormat = new TicketDataFormat(dataProtector);
			}
			if (options.CookieAuthenticationOptions.CookieManager == null)
			{
				options.CookieAuthenticationOptions.CookieManager = new ChunkingCookieManager();
			}
			if (!options.CookieAuthenticationOptions.LoginPath.HasValue)
			{
				options.CookieAuthenticationOptions.LoginPath = CookieAuthenticationDefaults.LoginPath;
			}
			if (!options.CookieAuthenticationOptions.LogoutPath.HasValue)
			{
				options.CookieAuthenticationOptions.LogoutPath = CookieAuthenticationDefaults.LogoutPath;
			}
			if (!options.CookieAuthenticationOptions.AccessDeniedPath.HasValue)
			{
				options.CookieAuthenticationOptions.AccessDeniedPath = CookieAuthenticationDefaults.AccessDeniedPath;
			}

			if (options.CookieAuthenticationOptions.Events == null)
				options.CookieAuthenticationOptions.Events = new CookieAuthenticationEvents();

			options.CookieAuthenticationOptions.Events.OnValidatePrincipal = options.OnValidateCookiePrincipal;
		}

		if (options.UseTokenAuthentication)
		{
			if (string.IsNullOrEmpty(options.TokenAuthenticationOptions.TokenValidationParameters.ValidAudience) && !string.IsNullOrEmpty(options.TokenAuthenticationOptions.Audience))
			{
				options.TokenAuthenticationOptions.TokenValidationParameters.ValidAudience = options.TokenAuthenticationOptions.Audience;
			}

			if (options.TokenAuthenticationOptions.ConfigurationManager == null)
			{
				if (options.TokenAuthenticationOptions.Configuration != null)
				{
					options.TokenAuthenticationOptions.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(options.TokenAuthenticationOptions.Configuration);
				}
				else if (!(string.IsNullOrEmpty(options.TokenAuthenticationOptions.MetadataAddress) && string.IsNullOrEmpty(options.TokenAuthenticationOptions.Authority)))
				{
					if (string.IsNullOrEmpty(options.TokenAuthenticationOptions.MetadataAddress) && !string.IsNullOrEmpty(options.TokenAuthenticationOptions.Authority))
					{
						options.TokenAuthenticationOptions.MetadataAddress = options.TokenAuthenticationOptions.Authority;
						if (!options.TokenAuthenticationOptions.MetadataAddress.EndsWith("/", StringComparison.Ordinal))
						{
							options.TokenAuthenticationOptions.MetadataAddress += "/";
						}

						options.TokenAuthenticationOptions.MetadataAddress += ".well-known/openid-configuration";
					}

					if (options.TokenAuthenticationOptions.RequireHttpsMetadata && !options.TokenAuthenticationOptions.MetadataAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
					{
						throw new InvalidOperationException("The MetadataAddress or Authority must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
					}

					var httpClient = new HttpClient(options.TokenAuthenticationOptions.BackchannelHttpHandler ?? new HttpClientHandler())
					{
						Timeout = options.TokenAuthenticationOptions.BackchannelTimeout,
						MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB
					};

					options.TokenAuthenticationOptions.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(options.TokenAuthenticationOptions.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
						new HttpDocumentRetriever(httpClient) { RequireHttps = options.TokenAuthenticationOptions.RequireHttpsMetadata });
				}
			}

			if (options.TokenAuthenticationOptions.Events == null)
				options.TokenAuthenticationOptions.Events = new JwtBearerEvents();

			options.TokenAuthenticationOptions.Events.OnTokenValidated = options.OnValidateTokenPrincipal;
		}

		if (options.UseRequestAuthentication)
		{
			if (options.RequestAuthenticationOptions.Events == null)
				options.RequestAuthenticationOptions.Events = new RequestAuth.Events.RequestAuthenticationEvents();

			options.RequestAuthenticationOptions.Events.OnValidatePrincipal = options.OnValidateRequestPrincipal;
		}

		options.SetAuthenticationFlow();

		if (options.AuthenticationFlowFallback.HasValue && !options.AuthenticationFlow.Contains(options.AuthenticationFlowFallback.Value))
			throw new InvalidOperationException($"{nameof(options.AuthenticationFlow)} does not contains {nameof(options.AuthenticationFlowFallback)} - {options.AuthenticationFlowFallback.Value}");
	}
}
