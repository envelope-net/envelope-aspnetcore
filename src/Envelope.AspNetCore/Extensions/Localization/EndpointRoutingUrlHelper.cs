using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using System.Globalization;

namespace Envelope.AspNetCore.Extensions.Localization;

internal class EndpointRoutingUrlHelper : UrlHelperBase
{
	private readonly ILogger<EndpointRoutingUrlHelper> _logger;

	private readonly LinkGenerator _linkGenerator;

	public EndpointRoutingUrlHelper(ActionContext actionContext, LinkGenerator linkGenerator, ILogger<EndpointRoutingUrlHelper> logger)
		: base(actionContext)
	{
		_linkGenerator = linkGenerator ?? throw new ArgumentNullException("linkGenerator");
		_logger = logger ?? throw new ArgumentNullException("logger");
	}

	public override string Action(UrlActionContext urlActionContext)
	{
		if (urlActionContext == null)
			throw new ArgumentNullException(nameof(urlActionContext));

		RouteValueDictionary routeValueDictionary = SetCulture(urlActionContext.Values);
		if (urlActionContext.Action == null)
		{
			if (!routeValueDictionary.ContainsKey("action") && AmbientValues.TryGetValue("action", out var value))
			{
				routeValueDictionary["action"] = value;
			}
		}
		else
		{
			routeValueDictionary["action"] = urlActionContext.Action;
		}

		if (urlActionContext.Controller == null)
		{
			if (!routeValueDictionary.ContainsKey("controller") && AmbientValues.TryGetValue("controller", out var value2))
			{
				routeValueDictionary["controller"] = value2;
			}
		}
		else
		{
			routeValueDictionary["controller"] = urlActionContext.Controller;
		}

		LinkGenerator linkGenerator = _linkGenerator;
		HttpContext httpContext = ActionContext.HttpContext;
		FragmentString fragment = new FragmentString(urlActionContext.Fragment == null ? null : "#" + urlActionContext.Fragment);
		string pathByRouteValues = linkGenerator.GetPathByRouteValues(httpContext, null, routeValueDictionary, null, fragment);
		return GenerateUrl(urlActionContext.Protocol, urlActionContext.Host, pathByRouteValues);
	}

	public override string RouteUrl(UrlRouteContext routeContext)
	{
		if (routeContext == null)
		{
			throw new ArgumentNullException("routeContext");
		}

		LinkGenerator linkGenerator = _linkGenerator;
		HttpContext httpContext = ActionContext.HttpContext;
		string? routeName = routeContext.RouteName;
		RouteValueDictionary values = SetCulture(routeContext.Values);
		FragmentString fragment = new FragmentString(routeContext.Fragment == null ? null : "#" + routeContext.Fragment);
		string pathByRouteValues = linkGenerator.GetPathByRouteValues(httpContext, routeName, values, null, fragment);
		return GenerateUrl(routeContext.Protocol, routeContext.Host, pathByRouteValues);
	}

	public override string Link(string routeName, object values)
	{
		return base.Link(routeName, SetCulture(values));
	}

	private RouteValueDictionary SetCulture(object? values)
	{
		RouteValueDictionary valuesDictionary = GetValuesDictionary(values);
		if (!valuesDictionary.ContainsKey("culture"))
		{
			valuesDictionary["culture"] = CultureInfo.CurrentCulture.Name;
		}

		return valuesDictionary;
	}
}
