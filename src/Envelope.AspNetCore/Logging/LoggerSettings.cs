namespace Envelope.AspNetCore.Logging;

public static class LoggerSettings
{
	internal const string Request = "Envelope_Request";
	internal const string Response = "Envelope_Response";
	internal const string RequestAuthentication = "Envelope_RequestAuthentication";

	internal const string Request_Template = "{@Envelope_Request}";
	internal const string Response_Template = "{@Envelope_Response}";
	internal const string RequestAuthentication_Template = "{@Envelope_RequestAuthentication}";
}
