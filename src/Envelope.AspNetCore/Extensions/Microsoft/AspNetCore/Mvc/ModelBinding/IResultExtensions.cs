using Envelope.AspNetCore;
using Envelope.Logging;
using Envelope.Services;
using Envelope.Trace;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;

namespace Envelope.Extensions;

public static class IResultExtensions
{
	public static bool MergeHasError(this IResult result, ITraceInfo traceInfo, ModelStateDictionary modelState)
	{
		if (result == null)
			throw new ArgumentNullException(nameof(result));

		if (modelState == null)
			throw new ArgumentNullException(nameof(modelState));

		if (modelState.IsValid)
			return false;

		foreach (var kvp in modelState)
		{
			var propertyName = kvp.Key;
			var errors = kvp.Value.Errors;
			if (errors != null)
			{
				foreach (var error in errors)
				{
					string msg;
					if (string.IsNullOrWhiteSpace(error.ErrorMessage))
					{
						msg = error.Exception == null
							? AspNetResources.DefaultModelStatePropertyError()
							: error.Exception.ToStringTrace();
					}
					else
					{
						msg = error.ErrorMessage;
					}

					result.ErrorMessages.Add(
						new ErrorMessageBuilder(traceInfo)
							.LogLevel(LogLevel.Error)
							.LogCode("MSTT_001")
							.IsValidationError(true)
							.ClientMessage(msg)
							.PropertyName(propertyName)
							.Build());
				}
			}
		}

		return result.HasError;
	}

	public static bool MergeHasTransactionRollbackError(this IResult result, ITraceInfo traceInfo, ModelStateDictionary modelState)
	{
		if (result == null)
			throw new ArgumentNullException(nameof(result));

		if (modelState == null)
			throw new ArgumentNullException(nameof(modelState));

		if (modelState.IsValid)
			return false;

		foreach (var kvp in modelState)
		{
			var propertyName = kvp.Key;
			var errors = kvp.Value.Errors;
			if (errors != null)
			{
				foreach (var error in errors)
				{
					string msg;
					if (string.IsNullOrWhiteSpace(error.ErrorMessage))
					{
						msg = error.Exception == null
							? AspNetResources.DefaultModelStatePropertyError()
							: error.Exception.ToStringTrace();
					}
					else
					{
						msg = error.ErrorMessage;
					}

					result.ErrorMessages.Add(
						new ErrorMessageBuilder(traceInfo)
							.LogLevel(LogLevel.Error)
							.LogCode("MSTT_001")
							.IsValidationError(true)
							.ClientMessage(msg)
							.PropertyName(propertyName)
							.Build());
				}
			}
		}

		return result.HasTransactionRollbackError;
	}

	public static bool MergeHasError<TResultBuilder>(this TResultBuilder resultBuilder, ITraceInfo traceInfo, ModelStateDictionary modelState)
		where TResultBuilder : IResultBuilder
	{
		if (resultBuilder == null)
			throw new ArgumentNullException(nameof(resultBuilder));

		if (modelState == null)
			throw new ArgumentNullException(nameof(modelState));

		if (modelState.IsValid)
			return false;

		foreach (var kvp in modelState)
		{
			var propertyName = kvp.Key;
			var errors = kvp.Value.Errors;
			if (errors != null)
			{
				foreach (var error in errors)
				{
					string msg;
					if (string.IsNullOrWhiteSpace(error.ErrorMessage))
					{
						msg = error.Exception == null
							? AspNetResources.DefaultModelStatePropertyError()
							: error.Exception.ToStringTrace();
					}
					else
					{
						msg = error.ErrorMessage;
					}

					resultBuilder.AddError(
						new ErrorMessageBuilder(traceInfo)
							.LogLevel(LogLevel.Error)
							.LogCode("MSTT_001")
							.IsValidationError(true)
							.ClientMessage(msg)
							.PropertyName(propertyName)
							.Build());
				}
			}
		}

		return resultBuilder.HasAnyError();
	}

	public static bool MergeHasTransactionRollbackError<TResultBuilder>(this TResultBuilder resultBuilder, ITraceInfo traceInfo, ModelStateDictionary modelState)
		where TResultBuilder : IResultBuilder
	{
		if (resultBuilder == null)
			throw new ArgumentNullException(nameof(resultBuilder));

		if (modelState == null)
			throw new ArgumentNullException(nameof(modelState));

		if (modelState.IsValid)
			return false;

		foreach (var kvp in modelState)
		{
			var propertyName = kvp.Key;
			var errors = kvp.Value.Errors;
			if (errors != null)
			{
				foreach (var error in errors)
				{
					string msg;
					if (string.IsNullOrWhiteSpace(error.ErrorMessage))
					{
						msg = error.Exception == null
							? AspNetResources.DefaultModelStatePropertyError()
							: error.Exception.ToStringTrace();
					}
					else
					{
						msg = error.ErrorMessage;
					}

					resultBuilder.AddError(
						new ErrorMessageBuilder(traceInfo)
							.LogLevel(LogLevel.Error)
							.LogCode("MSTT_001")
							.IsValidationError(true)
							.ClientMessage(msg)
							.PropertyName(propertyName)
							.Build());
				}
			}
		}

		return resultBuilder.HasAnyTransactionRollbackError();
	}
}
