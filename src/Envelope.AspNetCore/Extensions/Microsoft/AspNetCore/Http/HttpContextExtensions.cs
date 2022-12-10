using Envelope.Audit;
using Microsoft.AspNetCore.Http;

namespace Envelope.Extensions;

public static class HttpContextExtensions
{
	private static readonly string ApplicationEntryIDKey = "__Envelope.ApplicationEntry-ID__";
	private static readonly string ApplicationEntryToken = "__Envelope.ApplicationEntry-Token__";

	public static bool TryAddIdApplicationEntry(this HttpContext context, Guid idApplicationEntry)
		=> TryAddHttpContextItemIfNotExists(context, ApplicationEntryIDKey, idApplicationEntry);

	public static void SetIdApplicationEntry(this HttpContext context, Guid idApplicationEntry)
		=> SetHttpContextItem(context, ApplicationEntryIDKey, idApplicationEntry);

	public static Guid? GetIdApplicationEntry(this HttpContext context, Guid? defaultIdApplicationEntry = null)
		=> GetHttpContextItem<string, Guid?>(context, ApplicationEntryIDKey, defaultIdApplicationEntry);

	public static bool HasIdApplicationEntry(this HttpContext context)
		=> HasHttpContextItem(context, ApplicationEntryIDKey);

	public static bool TryAddApplicationEntryToken(this HttpContext context, ApplicationEntryToken token)
		=> TryAddHttpContextItemIfNotExists(context, ApplicationEntryToken, token);

	public static void SetApplicationEntryToken(this HttpContext context, ApplicationEntryToken token)
		=> SetHttpContextItem(context, ApplicationEntryToken, token);

	public static ApplicationEntryToken? GetApplicationEntryToken(this HttpContext context)
		=> GetHttpContextItem<string, ApplicationEntryToken?>(context, ApplicationEntryToken, null);

	public static bool HasApplicationEntryToken(this HttpContext context)
		=> HasHttpContextItem(context, ApplicationEntryToken);


	private static bool TryAddHttpContextItemIfNotExists<TKey, TValue>(HttpContext context, TKey key, TValue? value)
	{
		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (key == null)
			throw new ArgumentNullException(nameof(key));

		return context.Items.TryAdd(key, value);
	}

	private static void SetHttpContextItem<TKey, TValue>(HttpContext context, TKey key, TValue value)
	{
		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (key == null)
			throw new ArgumentNullException(nameof(key));

		context.Items[key] = value;
	}

	//private static bool TryGetHttpContextItem<TKey, TValue>(HttpContext context, TKey key, out TValue? value, TValue? defaultValue = default)
	//{
	//	if (context == null)
	//		throw new ArgumentNullException(nameof(context));

	//	if (key == null)
	//		throw new ArgumentNullException(nameof(key));

	//	if (context.Items.TryGetValue(key, out object? val))
	//	{
	//		value = (TValue?)val;
	//		return true;
	//	}
	//	else
	//	{
	//		value = defaultValue;
	//		return false;
	//	}
	//}

	private static TValue? GetHttpContextItem<TKey, TValue>(HttpContext context, TKey key, TValue? defaultValue = default)
	{
		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (key == null)
			throw new ArgumentNullException(nameof(key));

		if (context.Items.TryGetValue(key, out object? value))
			return (TValue?)value;

		return defaultValue;
	}

	private static bool HasHttpContextItem<TKey>(HttpContext context, TKey key)
	{
		if (context == null)
			throw new ArgumentNullException(nameof(context));

		if (key == null)
			throw new ArgumentNullException(nameof(key));

		return context.Items.ContainsKey(key);
	}

	//private static bool RemoveHttpContextItem<TKey>(HttpContext context, TKey key)
	//{
	//	if (context == null)
	//		throw new ArgumentNullException(nameof(context));

	//	if (key == null)
	//		throw new ArgumentNullException(nameof(key));

	//	return context.Items.Remove(key);
	//}
}
