using Envelope.Infrastructure;

namespace Envelope.AspNetCore.Logging.Dto;

public class RequestAuthentication<TIdentity> : Serializer.IDictionaryObject
	where TIdentity : struct
{
	public Guid RuntimeUniqueKey { get; set; }
	public DateTimeOffset CreatedUtc { get; set; }
	public Guid? CorrelationId { get; set; }
	public string? ExternalCorrelationId { get; set; }
	public TIdentity? IdUser { get; set; }
	public string? Roles { get; set; }
	public string? Permissions { get; set; }

	public RequestAuthentication()
	{
		RuntimeUniqueKey = EnvironmentInfo.RUNTIME_UNIQUE_KEY;
		CreatedUtc = DateTimeOffset.UtcNow;
	}

	public IDictionary<string, object?> ToDictionary(Serializer.ISerializer? serializer = null)
	{
		var dict = new Dictionary<string, object?>
		{
			{ nameof(RuntimeUniqueKey), RuntimeUniqueKey },
			{ nameof(CreatedUtc), CreatedUtc },
		};

		if (CorrelationId.HasValue)
			dict.Add(nameof(CorrelationId), CorrelationId);

		if (!string.IsNullOrWhiteSpace(ExternalCorrelationId))
			dict.Add(nameof(ExternalCorrelationId), ExternalCorrelationId);

		if (IdUser.HasValue)
			dict.Add(nameof(IdUser), IdUser);

		if (!string.IsNullOrWhiteSpace(Roles))
			dict.Add(nameof(Roles), Roles);

		if (!string.IsNullOrWhiteSpace(Permissions))
			dict.Add(nameof(Permissions), Permissions);

		return dict;
	}
}
