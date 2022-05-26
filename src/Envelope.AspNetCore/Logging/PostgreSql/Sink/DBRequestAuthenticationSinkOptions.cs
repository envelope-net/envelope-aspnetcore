using NpgsqlTypes;
using Envelope.AspNetCore.Logging.Dto;
using Envelope.Data;
using Envelope.Database.PostgreSql;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class DBRequestAuthenticationSinkOptions<TIdentity> : DbBatchWriterOptions, IBatchWriterOptions
	where TIdentity : struct
{
	public DBRequestAuthenticationSinkOptions()
	{
		TableName = nameof(RequestAuthentication<TIdentity>);

		PropertyNames = new List<string>
		{
			nameof(RequestAuthentication<TIdentity>.RuntimeUniqueKey),
			nameof(RequestAuthentication<TIdentity>.CreatedUtc),
			nameof(RequestAuthentication<TIdentity>.CorrelationId),
			nameof(RequestAuthentication<TIdentity>.ExternalCorrelationId),
			nameof(RequestAuthentication<TIdentity>.IdUser),
			nameof(RequestAuthentication<TIdentity>.Roles),
			nameof(RequestAuthentication<TIdentity>.Permissions)
		};

		PropertyTypeMapping = new Dictionary<string, NpgsqlDbType>
		{
			{ nameof(RequestAuthentication<TIdentity>.RuntimeUniqueKey), NpgsqlDbType.Uuid },
			{ nameof(RequestAuthentication<TIdentity>.CreatedUtc), NpgsqlDbType.TimestampTz },
			{ nameof(RequestAuthentication<TIdentity>.CorrelationId), NpgsqlDbType.Uuid },
			{ nameof(RequestAuthentication<TIdentity>.ExternalCorrelationId), NpgsqlDbType.Varchar },
			{ nameof(RequestAuthentication<TIdentity>.IdUser), NpgsqlDbTypeHelper.GetNpgsqlDbType<TIdentity>() },
			{ nameof(RequestAuthentication<TIdentity>.Roles), NpgsqlDbType.Varchar },
			{ nameof(RequestAuthentication<TIdentity>.Permissions), NpgsqlDbType.Varchar }
		};
	}
}
