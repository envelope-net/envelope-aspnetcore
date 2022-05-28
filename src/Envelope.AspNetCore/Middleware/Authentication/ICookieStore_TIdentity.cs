using Envelope.Trace;
using Microsoft.AspNetCore.Http;

namespace Envelope.AspNetCore.Middleware.Authentication;

public interface ICookieStore<TIdentity>
	where TIdentity : struct
{
	Task<bool> InsertAsync(HttpContext context, string authCookie, DateTime createdUtc, DateTime validToUtc, TIdentity? idUser, CancellationToken cancellationToken = default);
	Task<bool> ExistsAsync(HttpContext context, string authCookie, CancellationToken cancellationToken = default);
	Task DeleteAsync(HttpContext context, string authCookie, bool setDeletedFlag, CancellationToken cancellationToken = default);
	Task ClearAsync(ITraceInfo<TIdentity> traceInfo, bool setDeletedFlag, DateTime? expiredUtc, int? idUser, CancellationToken cancellationToken = default);
}
