namespace Envelope.AspNetCore.Middleware.Initialization;

public class RequestInitializationOptions<TIdentity>
	where TIdentity : struct
{
	public const string DefaultHeader = "X-Correlation-ID";

	public string Header { get; set; } = DefaultHeader;

	public bool UseCorrelationIdFromClient { get; set; } = false;

	public bool IncludeInResponse { get; set; } = true;

	public Func<IApplicationContext<TIdentity>, Task>? OnRequestInitialized { get; set; }
}
