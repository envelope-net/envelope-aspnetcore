using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Envelope.AspNetCore.Extensions.Localization;

public class CultureUrlHelperFactory : IUrlHelperFactory
{
	public IUrlHelper GetUrlHelper(ActionContext context)
	{
		if (context == null)
		{
			throw new ArgumentNullException("context");
		}

		HttpContext httpContext = context.HttpContext;
		if (httpContext == null)
		{
			throw new ArgumentException("HttpContext");
		}

		if (httpContext.Items == null)
		{
			throw new ArgumentException("Items");
		}

		if (httpContext.Items.TryGetValue(typeof(IUrlHelper), out var value))
		{
			if (value is IUrlHelper urlHelper)
				return urlHelper;
		}

		IUrlHelper urlHelper2;
		if (httpContext.Features.Get<IEndpointFeature>()?.Endpoint != null)
		{
			IServiceProvider requestServices = httpContext.RequestServices;
			LinkGenerator requiredService = requestServices.GetRequiredService<LinkGenerator>();
			ILogger<EndpointRoutingUrlHelper> requiredService2 = requestServices.GetRequiredService<ILogger<EndpointRoutingUrlHelper>>();
			urlHelper2 = new EndpointRoutingUrlHelper(context, requiredService, requiredService2);
		}
		else
		{
			urlHelper2 = new CultureUrlHelper(context);
		}

		httpContext.Items[typeof(IUrlHelper)] = urlHelper2;
		return urlHelper2;
	}
}
