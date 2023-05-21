using Envelope.Web.Logging;
using Microsoft.AspNetCore.Http;
using System.Text;

namespace Envelope.AspNetCore.Logging;

public static class RequestDtoFactory
{
	public static async Task<RequestDto> CreateAsync(
		HttpRequest httpRequest,
		string? remoteIp,
		Guid correlationId,
		string? externalCorrelationId,
		bool logRequestHeaders,
		bool logRequestForm,
		bool logRequestBodyAsString,
		bool logRequestBodyAsByteArray,
		bool logRequestFiles)
	{
		if (httpRequest == null)
			throw new ArgumentNullException(nameof(httpRequest));

		var request = new RequestDto
		{
			CorrelationId = correlationId,
			ExternalCorrelationId = externalCorrelationId,
			RemoteIp = remoteIp
		};

		try { request.Protocol = httpRequest.Protocol; } catch { }
		try { request.Scheme = httpRequest.Scheme; } catch { }
		try { request.Host = httpRequest.Host.ToString(); } catch { }
		try { request.Method = httpRequest.Method; } catch { }
		try { request.Path = httpRequest.Path; } catch { }
		try { request.QueryString = httpRequest.QueryString.ToString(); } catch { }
		try { request.ContentType = httpRequest.ContentType; } catch { }

		if (logRequestHeaders)
		{
			try
			{
				if (httpRequest.Headers != null)
				{
					var headers = new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(httpRequest.Headers);
					request.Headers = System.Text.Json.JsonSerializer.Serialize(headers);
				}
			}
			catch { }
		}

		if (logRequestForm)
		{
			try
			{
				if (httpRequest.HasFormContentType && httpRequest.Form != null)
				{
					var form = new List<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>>(httpRequest.Form);
					request.Form = System.Text.Json.JsonSerializer.Serialize(form);
				}
			}
			catch { }
		}

		if (logRequestBodyAsString)
		{
			var originalRequestBody = httpRequest.Body;
			try
			{
				var requestBodyStream = new MemoryStream();
				await httpRequest.Body.CopyToAsync(requestBodyStream).ConfigureAwait(false);
				requestBodyStream.Seek(0, SeekOrigin.Begin);

				//System.Net.Http.Headers
				Encoding? encoding = null;
				if (!string.IsNullOrWhiteSpace(request.ContentType))
				{
					try
					{
						if (Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType.TrimEnd(';'), out var mediaTypeHeaderValue))
						{
							var charset = mediaTypeHeaderValue.Charset.ToString();

							if (!string.IsNullOrWhiteSpace(charset))
								Encoding.GetEncoding(mediaTypeHeaderValue.Charset.ToString());
						}
					}
					catch { }
				}

				if (encoding == null)
				{
					request.Body = await new StreamReader(requestBodyStream).ReadToEndAsync();
				}
				else
				{
					request.Body = await new StreamReader(requestBodyStream, encoding).ReadToEndAsync();
				}

				if (string.IsNullOrWhiteSpace(request.Body))
					request.Body = null;

				if (originalRequestBody.CanSeek)
				{
					originalRequestBody.Seek(0, SeekOrigin.Begin);
					await requestBodyStream.DisposeAsync();
				}
				else
				{
					requestBodyStream.Seek(0, SeekOrigin.Begin);
					originalRequestBody = requestBodyStream;
				}
			}
			finally
			{
				httpRequest.Body = originalRequestBody;
			}
		}

		if (logRequestBodyAsByteArray)
		{
			var originalRequestBody = httpRequest.Body;
			try
			{
				var requestBodyStream = new MemoryStream();
				await httpRequest.Body.CopyToAsync(requestBodyStream).ConfigureAwait(false);
				requestBodyStream.Seek(0, SeekOrigin.Begin);
				request.BodyByteArray = requestBodyStream.ToArray();

				if (request.BodyByteArray != null && request.BodyByteArray.Length == 0)
					request.BodyByteArray = null;

				if (originalRequestBody.CanSeek)
				{
					originalRequestBody.Seek(0, SeekOrigin.Begin);
					await requestBodyStream.DisposeAsync();
				}
				else
				{
					requestBodyStream.Seek(0, SeekOrigin.Begin);
					originalRequestBody = requestBodyStream;
				}
			}
			finally
			{
				httpRequest.Body = originalRequestBody;
			}
		}

		if (logRequestFiles)
		{
			//TODO
		}

		return request;
	}
}
