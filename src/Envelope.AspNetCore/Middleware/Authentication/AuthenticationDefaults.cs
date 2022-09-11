namespace Envelope.AspNetCore.Middleware.Authentication;

public class AuthenticationDefaults
{
	public const string AUTHENTICATION_SCHEME = "EnvelopeAuth";
	public static string AuthenticationScheme { get; internal set; } = AUTHENTICATION_SCHEME;
}
