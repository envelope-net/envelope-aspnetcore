using Envelope.Audit;
using Envelope.Extensions;
using Envelope.Logging.PostgreSql;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Collections.Concurrent;
using System.Reflection;

namespace Envelope.AspNetCore.Filters;

public class ApplicationEntryPageFilter : IAsyncPageFilter, IOrderedFilter
{
	private readonly static Lazy<ConcurrentDictionary<MethodInfo, ApplicationEntryToken>> _methodInfoDict = new(() => new ConcurrentDictionary<MethodInfo, ApplicationEntryToken>());

	public int Order => int.MinValue;

	public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context)
	{
		return Task.CompletedTask;
	}

	public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
	{
		if (context.HandlerMethod?.MethodInfo?.GetCustomAttributes(typeof(ApplicationEntryAttribute), false).FirstOrDefault() is ApplicationEntryAttribute applicationEntryAttribute)
		{
			var methodInfo = context.HandlerMethod?.MethodInfo;
			if (methodInfo == null)
				throw new InvalidOperationException($"{nameof(methodInfo)} == null");

			if (!_methodInfoDict.Value.TryGetValue(methodInfo, out var token))
			{
				token = new ApplicationEntryToken(applicationEntryAttribute.Token, applicationEntryAttribute.Version)
				{
					MethodInfo = ((MethodBase?)methodInfo)?.GetMethodFullName(),
					MainEntityName = applicationEntryAttribute.EntityName,
					Description = applicationEntryAttribute.Description,
					TokenHistory = null
				};

				try
				{
					var dbToken = await DbLogWriter.Instance.GetApplicationEntryTokenAsync(token.Token, token.Version);
					if (dbToken == null)
					{
						DbLogWriter.Instance.WriteApplicationEntryToken(token.WriteToHistory());
					}
					else
					{
						dbToken.MethodInfo = token.MethodInfo;
						dbToken.MainEntityName = token.MainEntityName;
						dbToken.Description = token.Description;
						await DbLogWriter.Instance.UpdateApplicationEntryTokenAsync(dbToken.WriteToHistory());
					}
				}
				catch { }

				_methodInfoDict.Value.TryAdd(methodInfo!, token);
			}

			if (token != null)
				context.HttpContext.TryAddApplicationEntryToken(token);
		}

		await next.Invoke();
	}
}
