using Envelope.Web;
using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Tracking;

public class RequestTrackingOptions
{
	public bool LogRequest { get; set; }
	public bool LogRequestHeaders { get; set; }
	public bool LogRequestForm { get; set; }
	public bool LogRequestBody { get; set; }
	public bool LogRequestFiles { get; set; }
	public bool LogUnknownRequestContentTypes { get; set; }
	public bool LogAllRequestContentTypes { get; set; }
	public List<string>? LoggedRequestAsByteArrayContentTypes { get; set; }
	public List<string>? LoggedRequestAsStringContentTypes { get; set; }
	public List<string>? NotLoggedRequestPaths { get; set; }

	public bool LogResponse { get; set; }
	public bool LogResponseHeaders { get; set; }
	public bool LogResponseBody { get; set; }
	public bool LogUnknownResponseContentTypes { get; set; }
	public bool LogAllResponseContentTypes { get; set; }
	public List<string>? LoggedResponseAsByteArrayContentTypes { get; set; }
	public List<string>? LoggedResponseAsStringContentTypes { get; set; }
	public List<string>? NotLoggedResponsePaths { get; set; }

	public RequestTrackingOptions()
	{
		LoggedRequestAsStringContentTypes = ContentTypeHelper.StringContentTypes.ToList();
		LoggedResponseAsStringContentTypes = ContentTypeHelper.StringContentTypes.ToList();
	}

	public bool CanLogRequest(HttpRequest request, out bool bodyAsString)
	{
		if (request == null)
			throw new ArgumentNullException(nameof(request));

		return
			IsRequestContentTypeAllowed(request.ContentType, out bodyAsString)
			&& IsRequestPathAllowed(request.Path);
	}

	public bool CanLogResponse(string path, HttpResponse response, out bool bodyAsString)
	{
		if (response == null)
			throw new ArgumentNullException(nameof(response));

		return
			IsResponseContentTypeAllowed(response.ContentType, out bodyAsString)
			&& IsResponsePathAllowed(path);
	}

	private bool IsRequestContentTypeAllowed(string? contentType, out bool bodyAsString)
	{
		if (string.IsNullOrWhiteSpace(contentType))
		{
			bodyAsString = false;
			return LogUnknownRequestContentTypes;
		}
		else
		{
			if (0 < LoggedRequestAsStringContentTypes?.Count)
			{
				if (LoggedRequestAsStringContentTypes
						.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
								|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase)))
				{
					bodyAsString = true;
					return true;
				}

				if (0 < LoggedRequestAsByteArrayContentTypes?.Count)
				{
					bodyAsString = false;
					return LogAllRequestContentTypes
						|| LoggedRequestAsByteArrayContentTypes
							.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
									|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase));
				}
				else
				{
					bodyAsString = false;
					return LogAllRequestContentTypes;
				}
			}
			else
			{
				if (0 < LoggedRequestAsByteArrayContentTypes?.Count)
				{
					bodyAsString = false;
					return LogAllRequestContentTypes
						|| LoggedRequestAsByteArrayContentTypes
							.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
									|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase));
				}
				else
				{
					bodyAsString = false;
					return LogAllRequestContentTypes;
				}
			}
		}
	}

	private bool IsResponseContentTypeAllowed(string contentType, out bool bodyAsString)
	{
		if (string.IsNullOrWhiteSpace(contentType))
		{
			bodyAsString = false;
			return LogUnknownResponseContentTypes;
		}
		else
		{
			if (0 < LoggedResponseAsStringContentTypes?.Count)
			{
				if (LoggedResponseAsStringContentTypes
						.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
								|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase)))
				{
					bodyAsString = true;
					return true;
				}

				if (0 < LoggedResponseAsByteArrayContentTypes?.Count)
				{
					bodyAsString = false;
					return LogAllResponseContentTypes
						|| LoggedResponseAsByteArrayContentTypes
							.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
									|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase));
				}
				else
				{
					bodyAsString = false;
					return LogAllResponseContentTypes;
				}
			}
			else
			{
				if (0 < LoggedResponseAsByteArrayContentTypes?.Count)
				{
					bodyAsString = false;
					return LogAllResponseContentTypes
						|| LoggedResponseAsByteArrayContentTypes
							.Any(x => -1 < x.IndexOf(contentType, StringComparison.OrdinalIgnoreCase)
									|| -1 < contentType.IndexOf(x, StringComparison.OrdinalIgnoreCase));
				}
				else
				{
					bodyAsString = false;
					return LogAllResponseContentTypes;
				}
			}
		}
	}

	private bool IsRequestPathAllowed(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return true;
		}
		else
		{
			if (0 < NotLoggedRequestPaths?.Count)
			{
				return NotLoggedRequestPaths.Any(x => path.StartsWith(x, StringComparison.OrdinalIgnoreCase));
			}
			else
			{
				return true;
			}
		}
	}

	private bool IsResponsePathAllowed(string path)
	{
		if (string.IsNullOrWhiteSpace(path))
		{
			return true;
		}
		else
		{
			if (0 < NotLoggedResponsePaths?.Count)
			{
				return NotLoggedResponsePaths.Any(x => path.StartsWith(x, StringComparison.OrdinalIgnoreCase));
			}
			else
			{
				return true;
			}
		}
	}
}
