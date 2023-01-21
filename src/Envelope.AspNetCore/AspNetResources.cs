namespace Envelope.AspNetCore;

public static class AspNetResources
{
	public static Func<string> DefaultModelStatePropertyError { get; set; } = () => "Error";
}
