using NpgsqlTypes;
using Envelope.Data;
using Envelope.Database.PostgreSql;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class DBRequestSinkOptions : DbBatchWriterOptions, IBatchWriterOptions
{
	public DBRequestSinkOptions()
	{
		TableName = nameof(RequestDto);

		PropertyNames = new List<string>
		{
			nameof(RequestDto.RuntimeUniqueKey),
			nameof(RequestDto.CreatedUtc),
			nameof(RequestDto.CorrelationId),
			nameof(RequestDto.ExternalCorrelationId),
			nameof(RequestDto.Protocol),
			nameof(RequestDto.Scheme),
			nameof(RequestDto.Host),
			nameof(RequestDto.RemoteIp),
			nameof(RequestDto.Method),
			nameof(RequestDto.Path),
			nameof(RequestDto.QueryString),
			nameof(RequestDto.Headers),
			nameof(RequestDto.ContentType),
			nameof(RequestDto.Body),
			nameof(RequestDto.BodyByteArray),
			nameof(RequestDto.Form),
			nameof(RequestDto.Files)
		};

		PropertyTypeMapping = new Dictionary<string, NpgsqlDbType>
		{
			{ nameof(RequestDto.RuntimeUniqueKey), NpgsqlDbType.Uuid },
			{ nameof(RequestDto.CreatedUtc), NpgsqlDbType.TimestampTz },
			{ nameof(RequestDto.CorrelationId), NpgsqlDbType.Uuid },
			{ nameof(RequestDto.ExternalCorrelationId), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Protocol), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Scheme), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Host), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.RemoteIp), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Method), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Path), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.QueryString), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Headers), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.ContentType), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Body), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.BodyByteArray), NpgsqlDbType.Bytea },
			{ nameof(RequestDto.Form), NpgsqlDbType.Varchar },
			{ nameof(RequestDto.Files), NpgsqlDbType.Varchar }
		};
	}
}
