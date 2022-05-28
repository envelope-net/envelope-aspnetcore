using NpgsqlTypes;
using Envelope.AspNetCore.Logging.Dto;
using Envelope.Data;
using Envelope.Database.PostgreSql;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class DBRequestAuthenticationSinkOptions : DbBatchWriterOptions, IBatchWriterOptions
{
	public DBRequestAuthenticationSinkOptions()
	{
		TableName = nameof(RequestAuthentication);

		PropertyNames = new List<string>
		{
			nameof(RequestAuthentication.RuntimeUniqueKey),
			nameof(RequestAuthentication.CreatedUtc),
			nameof(RequestAuthentication.CorrelationId),
			nameof(RequestAuthentication.ExternalCorrelationId),
			nameof(RequestAuthentication.IdUser),
			nameof(RequestAuthentication.Roles),
			nameof(RequestAuthentication.Permissions)
		};

		PropertyTypeMapping = new Dictionary<string, NpgsqlDbType>
		{
			{ nameof(RequestAuthentication.RuntimeUniqueKey), NpgsqlDbType.Uuid },
			{ nameof(RequestAuthentication.CreatedUtc), NpgsqlDbType.TimestampTz },
			{ nameof(RequestAuthentication.CorrelationId), NpgsqlDbType.Uuid },
			{ nameof(RequestAuthentication.ExternalCorrelationId), NpgsqlDbType.Varchar },
			{ nameof(RequestAuthentication.IdUser), NpgsqlDbTypeHelper.GetNpgsqlDbType<Guid>() },
			{ nameof(RequestAuthentication.Roles), NpgsqlDbType.Varchar },
			{ nameof(RequestAuthentication.Permissions), NpgsqlDbType.Varchar }
		};
	}
}
