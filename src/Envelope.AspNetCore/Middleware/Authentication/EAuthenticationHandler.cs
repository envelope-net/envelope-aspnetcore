using Envelope.Exceptions;
using Envelope.Logging.Extensions;
using Envelope.Trace;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace Envelope.AspNetCore.Middleware.Authentication;

internal class EAuthenticationHandler : AuthenticationHandler<EAuthenticationOptions>
{
	private readonly IServiceScopeFactory _serviceScopeFactory;

	public EAuthenticationHandler(
		IOptionsMonitor<EAuthenticationOptions> options,
		ILoggerFactory logger,
		UrlEncoder encoder,
		ISystemClock clock,
		IServiceScopeFactory serviceScopeFactory)
		: base(options, logger, encoder, clock)
	{
		Throw.ArgumentNull(serviceScopeFactory);
		_serviceScopeFactory = serviceScopeFactory;
	}

	protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
	{
		IServiceProvider? serviceProvider = null;
		try
		{
			if (Options.AuthenticationServiceFactory == null)
				Throw.IfNull(Options.AuthenticationServiceFactory);

			using var scope = _serviceScopeFactory.CreateScope();
			serviceProvider = scope.ServiceProvider;

			var authenticationService = Options.AuthenticationServiceFactory.Invoke(serviceProvider);

			Throw.IfNull(authenticationService);

			var principal = await authenticationService.AuthenticateAsync(
				Scheme,
				this,
				serviceProvider,
				Context,
				Options,
				Logger,
				UrlEncoder,
				Clock);

			if (principal?.Identity?.IsAuthenticated == true)
			{
				var ticket = new AuthenticationTicket(principal, this.Scheme.Name);
				return AuthenticateResult.Success(ticket);
			}
			else
			{
				return AuthenticateResult.Fail($"Authentication failed for scheme '{this.Scheme.Name}'");
			}
		}
		catch (Exception ex)
		{
			if (serviceProvider == null)
			{
				using var scope = _serviceScopeFactory.CreateScope();
				serviceProvider = scope.ServiceProvider;
			}

			var appCtx = serviceProvider.GetRequiredService<IApplicationContext>();
			Logger.LogErrorMessage(TraceInfo.Create(appCtx), x => x.ExceptionInfo(ex).Detail($"Authentication failed for scheme '{this.Scheme.Name}'"));
			throw;
		}
	}
}
