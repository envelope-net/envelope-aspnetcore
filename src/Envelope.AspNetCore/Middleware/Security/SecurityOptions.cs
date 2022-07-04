namespace Envelope.AspNetCore.Middleware.Security;

public class SecurityOptions
{
	private readonly Dictionary<string, IResponseHeaderOptions> _removeHeaders;
	private readonly Dictionary<string, IResponseHeaderOptions> _addHeaders;

	public IReadOnlyDictionary<string, IResponseHeaderOptions> RemoveHeaders => _removeHeaders;
	public IReadOnlyDictionary<string, IResponseHeaderOptions> AddHeaders => _addHeaders;

	public SecurityOptions()
	{
		_removeHeaders = new Dictionary<string, IResponseHeaderOptions>();
		_addHeaders = new Dictionary<string, IResponseHeaderOptions>();
	}

	public SecurityOptions SetHeader(IResponseHeaderOptions headerOptions)
	{
		if (headerOptions == null)
			throw new ArgumentNullException(nameof(headerOptions));

		if (headerOptions.Remove)
			_removeHeaders[headerOptions.Key] = headerOptions;
		else
			_addHeaders[headerOptions.Key] = headerOptions;

		return this;
	}

	public SecurityOptions AddHeader(IResponseHeaderOptions headerOptions)
	{
		if (headerOptions == null)
			throw new ArgumentNullException(nameof(headerOptions));

		if (headerOptions.Remove)
			throw new InvalidOperationException($"{nameof(headerOptions)} must have a value.");

		_addHeaders[headerOptions.Key] = headerOptions;
		return this;
	}

	public SecurityOptions RemoveHeader(IResponseHeaderOptions headerOptions)
	{
		if (headerOptions == null)
			throw new ArgumentNullException(nameof(headerOptions));

		if (!headerOptions.Remove)
			throw new InvalidOperationException($"{nameof(headerOptions)} must not have a value.");

		_removeHeaders[headerOptions.Key] = headerOptions;
		return this;
	}

	public SecurityOptions SetDefaultWebOptions()
		=> this
			.SetHeader(ResponseHeaderOptions.ReferrerPolicy)
			.SetHeader(ResponseHeaderOptions.XContentTypeOptions)
			.SetHeader(ResponseHeaderOptions.XFrameOptions_SAMEORIGIN)
			.SetHeader(ResponseHeaderOptions.XPermittedCrossDomainPolicies)
			.SetHeader(ResponseHeaderOptions.XXssProtection)
			//.SetHeader(ResponseHeaderOptions.ExpectCT)
			.SetHeader(ResponseHeaderOptions.FeaturePolicy)
			//.SetHeader(ResponseHeaderOptions.ContentSecurityPolicy)
			.SetHeader(ResponseHeaderOptions.RemoveSerever);

	public SecurityOptions SetDefaultWebApiOptions(string swaggerPath = "/swagger")
		=> this
			.SetHeader(ResponseHeaderOptions.ReferrerPolicy)
			.SetHeader(ResponseHeaderOptions.XContentTypeOptions)
			.SetHeader(ResponseHeaderOptions.XFrameOptions_DENY)
			.SetHeader(ResponseHeaderOptions.XPermittedCrossDomainPolicies)
			.SetHeader(ResponseHeaderOptions.XXssProtection)
			//.SetHeader(ResponseHeaderOptions.ExpectCT)
			.SetHeader(ResponseHeaderOptions.FeaturePolicy)
			.SetHeader(ResponseHeaderOptions.ContentSecurityPolicy.IgnoredPath(swaggerPath))
			.SetHeader(ResponseHeaderOptions.RemoveSerever);
}
