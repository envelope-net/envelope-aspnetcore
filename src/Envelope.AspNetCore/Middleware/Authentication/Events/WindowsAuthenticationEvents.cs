#nullable disable

namespace Envelope.AspNetCore.Middleware.Authentication.Events;

public class WindowsAuthenticationEvents
{
	/// <summary>
	/// A delegate assigned to this property will be invoked when the related method is called.
	/// </summary>
	public Func<WindowsValidatePrincipalContext, Task> OnValidatePrincipal { get; set; }
														//context => 
														//	throw new InvalidOperationException($"{nameof(OnValidatePrincipal)} is not set.");
														//Task.CompletedTask;

	/// <summary>
	/// Implements the interface method by invoking the related delegate method.
	/// </summary>
	/// <param name="context"></param>
	/// <returns></returns>
	public virtual Task ValidatePrincipalAsync(WindowsValidatePrincipalContext context) => OnValidatePrincipal == null
		? throw new InvalidOperationException($"{nameof(OnValidatePrincipal)} is not set.")
		: OnValidatePrincipal(context);
}
