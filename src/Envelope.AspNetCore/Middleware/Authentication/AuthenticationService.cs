using Microsoft.AspNetCore.DataProtection;
using Envelope.AspNetCore.Identity;
using Envelope.AspNetCore.Logging;
using Envelope.Extensions;
using Envelope.Identity;
using Envelope.Trace;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Envelope.Converters;

namespace Envelope.AspNetCore.Authentication;

public static class AuthenticationService
{
	private static Dictionary<string, string>? _cookieDataProtectionPurposes; //Dictionary<cookieName, purpose>
	private static bool _dataProtectorsCreated = false;
	private static ConcurrentDictionary<string, IDataProtector>? _dataProtectors; //Dictionary<cookieName, IDataProtector>

	private static readonly object _initLock = new();
	private static bool _initialized = false;
	public static void Initialize(Dictionary<string, string>? cookieDataProtectionPurposes)
	{
		if (_initialized)
			throw new InvalidOperationException("Already initialized");

		lock (_initLock)
		{
			if (_initialized)
				throw new InvalidOperationException("Already initialized");

			_cookieDataProtectionPurposes = cookieDataProtectionPurposes;
			_initialized = true;
		}
	}

	public static IDataProtector? GetDataProtector(HttpContext context, string cookieName)
	{
		if (!_dataProtectorsCreated)
			GetDataProtectors(context);

		return GetDataProtector(cookieName);
	}

	public static IDataProtector? GetDataProtector(string cookieName)
	{
		if (_dataProtectors == null)
			return null;

		_dataProtectors.TryGetValue(cookieName, out IDataProtector? dataProtector);
		return dataProtector;
	}

	public static IReadOnlyDictionary<string, IDataProtector>? GetDataProtectors(HttpContext context)
	{
		if (context == null)
			return null;

		if (_dataProtectorsCreated)
			return _dataProtectors;

		if (_cookieDataProtectionPurposes == null)
			return null;

		_dataProtectors = new ConcurrentDictionary<string, IDataProtector>();
		var dataProtectionProvider = context.RequestServices.GetRequiredService<IDataProtectionProvider>();

		foreach (var kvp in _cookieDataProtectionPurposes)
		{
			var dataProtector = dataProtectionProvider.CreateProtector(kvp.Value);
			_dataProtectors.TryAdd(kvp.Key, dataProtector);
		}

		_dataProtectorsCreated = true;
		return _dataProtectors;
	}

	private static ILogger GetLogger(HttpContext context)
	{
		var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
		var logger = loggerFactory.CreateLogger(typeof(AuthenticationService).FullName!);
		return logger;
	}

	public static async Task<EnvelopePrincipal?> CreateFromWindowsIdentityAsync(HttpContext context, string authenticationSchemeType, bool allowStaticLogin)
	{
		if (!OperatingSystem.IsWindows())
			return null;

		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (string.IsNullOrWhiteSpace(authenticationSchemeType))
			throw new ArgumentNullException(nameof(authenticationSchemeType));

		//if (logger == null)
		//	logger = GetLogger(context);

		WindowsPrincipal? windowsPrincipal = context.User as WindowsPrincipal;

		IIdentity? identity = null;
		string? logonWithoutDomain;
		string? windowsIdentityName = null;
		AuthenticatedUser? user = null;

		IAuthenticationManager? authenticationManager = null;
		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();
		if (windowsPrincipal?.Identity is WindowsIdentity windowsIdentity)
		{
			logonWithoutDomain = windowsIdentity.GetLogonNameWithoutDomain().ToLower();
			windowsIdentityName = windowsIdentity.Name.ToLower();

			authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
			user = await authenticationManager.CreateFromWindowsIdentityAsync(logonWithoutDomain, windowsIdentityName, applicationContext.RequestMetadata).ConfigureAwait(false);
		}

		if (user == null)
			return await CreateStaticAsync(context, authenticationSchemeType, /*logger,*/ allowStaticLogin).ConfigureAwait(false);

		if (user != null && !string.IsNullOrWhiteSpace(windowsIdentityName))
		{
			var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, windowsIdentityName));
			identity = claimsIdentity;
		}

		return CreateEnvelopePrincipal(identity, user, true, true, /*logger,*/ applicationContext, authenticationManager);
	}

	public static async Task<EnvelopePrincipal?> CreateFromRequestAsync(HttpContext context, string authenticationSchemeType)
	{
		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (string.IsNullOrWhiteSpace(authenticationSchemeType))
			throw new ArgumentNullException(nameof(authenticationSchemeType));

		//if (logger == null)
		//	logger = GetLogger(context);

		IIdentity? identity = null;
		var authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();

		var user = await authenticationManager.CreateFromRequestAsync(applicationContext.RequestMetadata).ConfigureAwait(false);

		if (user != null && !string.IsNullOrWhiteSpace(user.Login))
		{
			var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
			identity = claimsIdentity;
		}

		return CreateEnvelopePrincipal(identity, user, true, true, /*logger,*/ applicationContext, authenticationManager);
	}

	public static async Task<EnvelopePrincipal?> CreateStaticAsync(HttpContext context, string authenticationSchemeType, bool allowStaticLogin)
	{
		if (!allowStaticLogin)
			return null;

		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (string.IsNullOrWhiteSpace(authenticationSchemeType))
			throw new ArgumentNullException(nameof(authenticationSchemeType));

		//if (logger == null)
		//	logger = GetLogger(context);

		IIdentity? identity = null;
		AuthenticatedUser? user = null;

		var authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();
		if (authenticationManager.StaticUserId.HasValue)
			user = await authenticationManager.CreateFromUserIdAsync(authenticationManager.StaticUserId, applicationContext.RequestMetadata).ConfigureAwait(false);

		if (user != null && !string.IsNullOrWhiteSpace(user.Login))
		{
			var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
			identity = claimsIdentity;
		}

		return CreateEnvelopePrincipal(identity, user, true, true, /*logger,*/ applicationContext, authenticationManager);
	}

	public static async Task<EnvelopePrincipal?> RenewTokenIdentityAsync(HttpContext context, ClaimsPrincipal? principal, ILogger? logger)
	{
		if (principal == null)
			return null;

		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (logger == null)
			logger = GetLogger(context);

		var userIdClaim =
			principal
				.Claims
				.FirstOrDefault(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.USER_ID_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		if (userIdClaim == null || !ConverterHelper.TryConvertFrom(userIdClaim.Value, out Guid userId))
			return null;

		var loginClaim =
			principal
				.Claims
				.FirstOrDefault(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.LOGIN_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		if (loginClaim == null)
			return null;

		var displayNameClaim =
			principal
				.Claims
				.FirstOrDefault(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.DISPLAYNAME_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		if (displayNameClaim == null)
			return null;

		var roleClaims =
			principal
				.Claims
				.Where(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.ROLE_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		var roleIdClaims =
			principal
				.Claims
				.Where(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.ROLE_ID_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		var premissionClaims =
			principal
				.Claims
				.Where(c => EnvelopeIdentity.IsEnvelopeClaim(c)
					&& string.Equals(c.Type, EnvelopeIdentity.PERMISSION_CLAIM_NAME, StringComparison.OrdinalIgnoreCase));

		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();

		var roleIds = roleIdClaims?.Select(c => ConverterHelper.ConvertFrom<Guid>(c.Value)).ToList();

		var user = new AuthenticatedUser(userId, loginClaim.Value, displayNameClaim.Value, applicationContext.Next())
		{
			UserData = null,
			Roles = roleClaims?.Select(c => c.Value).ToList(),
			RoleIds = roleIds,
			Permissions = premissionClaims?.Select(c => c.Value).ToList()
		};

		var authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
		user = await authenticationManager.SetUserDataAsync(user, applicationContext.RequestMetadata, roleIds).ConfigureAwait(false);
		
		return CreateEnvelopePrincipal(principal.Identity, user, true, true, /*logger,*/ applicationContext, authenticationManager);
	}

	public static async Task<EnvelopePrincipal?> CreateIdentityAsync(HttpContext context, string? login, string? password, string authenticationSchemeType /*, out string? error, out string? passwordTemporaryUrlSlug*/)
	{
		//error = null;
		//passwordTemporaryUrlSlug = null;

		if (string.IsNullOrWhiteSpace(login))
			return null;

		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (string.IsNullOrWhiteSpace(authenticationSchemeType))
			throw new ArgumentNullException(nameof(authenticationSchemeType));

		//if (logger == null)
		//	logger = GetLogger(context);

		var authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
		var user = await authenticationManager.CreateFromLoginPasswordAsync(login, password).ConfigureAwait(false);
		if (user == null)
			return null;

		var success = PasswordHelper.VerifyHashedPassword(user.Password, user.Salt, password);
		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();

		if (success)
		{
			//error = user.Error;
			//passwordTemporaryUrlSlug = user.PasswordTemporaryUrlSlug;

			user = await authenticationManager.SetUserDataRolesPremissionsAsync(user, applicationContext.RequestMetadata).ConfigureAwait(false);
		}
		else
		{
			user.UserData = null;
			return null;
		}

		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, login));
		return CreateEnvelopePrincipal(claimsIdentity, user, false, false, /*logger,*/ applicationContext, authenticationManager);
	}

	public static async Task<EnvelopePrincipal?> RecreateCookieIdentityAsync(HttpContext context, string? userName, string authenticationSchemeType, ILogger logger)
	{
		if (string.IsNullOrWhiteSpace(userName))
			return null;

		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (string.IsNullOrWhiteSpace(authenticationSchemeType))
			throw new ArgumentNullException(nameof(authenticationSchemeType));

		//if (logger == null)
		//	logger = GetLogger(context);

		var authenticationManager = context.RequestServices.GetRequiredService<IAuthenticationManager>();
		var applicationContext = context.RequestServices.GetRequiredService<IApplicationContext>();
		var user = await authenticationManager.CreateFromLoginAsync(userName.ToLower(), applicationContext.RequestMetadata).ConfigureAwait(false);
		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, userName));
		return CreateEnvelopePrincipal(claimsIdentity, user, true, true, /*logger,*/ applicationContext, authenticationManager);
	}

	#region withhout HttpContext

	//public static async Task<EnvelopePrincipal?> CreateFromWindowsIdentityAsync(string authenticationSchemeType, ILogger? logger)
	//{
	//	if (authenticationManager == null)
	//		throw new InvalidOperationException("Not initialized");

	//	if (!OperatingSystem.IsWindows())
	//		return null;

	//	if (string.IsNullOrWhiteSpace(authenticationSchemeType))
	//		throw new ArgumentNullException(nameof(authenticationSchemeType));

	//	string? logonWithoutDomain;
	//	string? windowsIdentityName;
	//	IIdentity? identity = null;

	//	try
	//	{
	//		var windowsIdentity = WindowsIdentity.GetCurrent();
	//		if (windowsIdentity != null)
	//		{
	//			logonWithoutDomain = windowsIdentity.GetLogonNameWithoutDomain().ToLower();
	//			windowsIdentityName = windowsIdentity.Name.ToLower();
	//		}
	//		else
	//		{
	//			logonWithoutDomain = Environment.UserName?.ToLower();
	//			windowsIdentityName = Environment.UserDomainName?.ToLower() + "\\" + Environment.UserName?.ToLower();

	//			var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
	//			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, windowsIdentityName));
	//			identity = claimsIdentity;
	//		}
	//	}
	//	catch
	//	{
	//		logonWithoutDomain = Environment.UserName?.ToLower();
	//		windowsIdentityName = Environment.UserDomainName?.ToLower() + "\\" + Environment.UserName?.ToLower();

	//		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
	//		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, windowsIdentityName));
	//		identity = claimsIdentity;
	//	}

	//	var user = await authenticationManager.CreateFromWindowsIdentityAsync(logonWithoutDomain, windowsIdentityName).ConfigureAwait(false);
	//	return CreateEnvelopePrincipal(identity, user, true, true);
	//}

	//public static async Task<EnvelopePrincipal?> CreateFakeIdentityAsync(TIdentity? idUser, string authenticationSchemeType, ILogger? logger)
	//{
	//	if (authenticationManager == null)
	//		throw new InvalidOperationException("Not initialized");

	//	if (string.IsNullOrWhiteSpace(authenticationSchemeType))
	//		throw new ArgumentNullException(nameof(authenticationSchemeType));

	//	var user = await authenticationManager.CreateFromUserIdAsync(idUser).ConfigureAwait(false);
	//	if (user == null)
	//		return null;

	//	var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
	//	claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
	//	return CreateEnvelopePrincipal(claimsIdentity, user, false, false);
	//}

	#endregion withhout HttpContext

	public static ClaimsPrincipal CreateAnonymousUser(string authenticationSchemeType, IApplicationContext applicationContext)
	{
		var user = new Envelope.Identity.AnonymousUser(TraceInfo.Create(applicationContext));
		var claimsIdentity = new ClaimsIdentity(authenticationSchemeType);
		claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Login));
		return new ClaimsPrincipal(claimsIdentity);
	}

	[return: NotNullIfNotNull("identity")]
	[return: NotNullIfNotNull("authenticatedUser")]
	private static EnvelopePrincipal? CreateEnvelopePrincipal(
		IIdentity? identity,
		AuthenticatedUser? authenticatedUser,
		bool rolesToClams,
		bool permissionsToClaims,
		IApplicationContext? applicationContext,
		IAuthenticationManager? authenticationManager)
	{
		if (identity == null || authenticatedUser == null)
			return null;

		var envelopeIdentity = new EnvelopeIdentity(
			identity,
			authenticatedUser.UserId,
			authenticatedUser.Login,
			authenticatedUser.DisplayName,
			authenticatedUser.UserData,
			authenticatedUser.IsSuperAdmin,
			authenticatedUser.Roles,
			authenticatedUser.RoleIds,
			authenticatedUser.Permissions,
			authenticatedUser.PermissionIds,
			rolesToClams,
			permissionsToClaims);

		if (authenticationManager?.LogRequestAuthentication ?? false)
		{
			AspNetLogWriter.Instance.WriteRequestAuthentication(new Logging.Dto.RequestAuthentication
			{
				CorrelationId = authenticatedUser.TraceInfo.CorrelationId,
				ExternalCorrelationId = authenticatedUser.TraceInfo.ExternalCorrelationId,
				IdUser = envelopeIdentity.UserId,
				Roles = authenticationManager.LogRoles
				? ((0 < envelopeIdentity.RoleIds?.Count)
					? System.Text.Json.JsonSerializer.Serialize(envelopeIdentity.RoleIds)
					: (0 < envelopeIdentity.Roles?.Count ? System.Text.Json.JsonSerializer.Serialize(envelopeIdentity.Roles) : null))
				: null,
				Permissions = authenticationManager.LogPermissions
				? ((0 < envelopeIdentity.PermissionIds?.Count)
					? System.Text.Json.JsonSerializer.Serialize(envelopeIdentity.PermissionIds)
					: (0 < envelopeIdentity.Permissions?.Count ? System.Text.Json.JsonSerializer.Serialize(envelopeIdentity.Permissions) : null))
				: null
			});
		}

		var envelopePrincipal = new EnvelopePrincipal(envelopeIdentity);

		if (applicationContext != null)
			applicationContext.AddTraceFrame(TraceInfo.Create(authenticatedUser.TraceInfo).TraceFrame, envelopePrincipal);

		return envelopePrincipal;
	}
}
