using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using System.Globalization;

namespace Envelope.AspNetCore.Extensions.Localization;

public class CultureUrlHelper : UrlHelper
{
	public CultureUrlHelper(ActionContext actionContext)
		: base(actionContext)
	{
	}

	public override string? Action(UrlActionContext actionContext)
	{
		if (actionContext == null)
			throw new ArgumentNullException(nameof(actionContext));

		actionContext.Values = SetCulture(actionContext.Values);
		return base.Action(actionContext);
	}

	public override string? RouteUrl(UrlRouteContext routeContext)
	{
		if (routeContext == null)
			throw new ArgumentNullException(nameof(routeContext));

		routeContext.Values = SetCulture(routeContext.Values);
		return base.RouteUrl(routeContext);
	}

	public override string? Link(string? routeName, object? values)
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
