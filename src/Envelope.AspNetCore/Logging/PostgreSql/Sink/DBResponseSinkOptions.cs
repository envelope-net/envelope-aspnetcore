using NpgsqlTypes;
using Envelope.Data;
using Envelope.Database.PostgreSql;
using Envelope.Web.Logging;

namespace Envelope.AspNetCore.Logging.PostgreSql.Sink;

public class DBResponseSinkOptions : DbBatchWriterOptions, IBatchWriterOptions
{
	public DBResponseSinkOptions()
	{
		TableName = nameof(ResponseDto);

		PropertyNames = new List<string>
		{
			nameof(ResponseDto.RuntimeUniqueKey),
			nameof(ResponseDto.CreatedUtc),
			nameof(ResponseDto.CorrelationId),
			nameof(ResponseDto.ExternalCorrelationId),
			nameof(ResponseDto.StatusCode),
			nameof(ResponseDto.Headers),
			nameof(ResponseDto.ContentType),
			nameof(ResponseDto.Body),
			nameof(ResponseDto.BodyByteArray),
			nameof(ResponseDto.Error),
			nameof(ResponseDto.ElapsedMilliseconds)
		};

		PropertyTypeMapping = new Dictionary<string, NpgsqlDbType>
		{
			{ nameof(ResponseDto.RuntimeUniqueKey), NpgsqlDbType.Uuid },
			{ nameof(ResponseDto.CreatedUtc), NpgsqlDbType.TimestampTz },
			{ nameof(ResponseDto.CorrelationId), NpgsqlDbType.Uuid },
			{ nameof(ResponseDto.ExternalCorrelationId), NpgsqlDbType.Varchar },
			{ nameof(ResponseDto.StatusCode), NpgsqlDbType.Integer },
			{ nameof(ResponseDto.Headers), NpgsqlDbType.Varchar },
			{ nameof(ResponseDto.ContentType), NpgsqlDbType.Varchar },
			{ nameof(ResponseDto.Body), NpgsqlDbType.Varchar },
			{ nameof(ResponseDto.BodyByteArray), NpgsqlDbType.Bytea },
			{ nameof(ResponseDto.Error), NpgsqlDbType.Varchar },
			{ nameof(ResponseDto.ElapsedMilliseconds), NpgsqlDbType.Numeric }
		};
	}
}
