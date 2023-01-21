using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace Envelope.AspNetCore.Extensions.Localization;

public class CultureRouteModelConvention : IPageRouteModelConvention, IPageConvention
{
	public void Apply(PageRouteModel model)
	{
		int count = model.Selectors.Count;
		for (int i = 0; i < count; i++)
		{
			SelectorModel selectorModel = model.Selectors[i];
			if (!string.IsNullOrWhiteSpace(selectorModel.AttributeRouteModel!.Template))
			{
				model.Selectors.Add(new SelectorModel
				{
					AttributeRouteModel = new AttributeRouteModel
					{
						Order = -1,
						Template = AttributeRouteModel.CombineTemplates("{culture?}", selectorModel.AttributeRouteModel!.Template)
					}
				});
			}
		}
	}
}
