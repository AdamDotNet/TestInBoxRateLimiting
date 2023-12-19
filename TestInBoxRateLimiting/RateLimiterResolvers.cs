using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace TestInBoxRateLimiting
{
	// TODO: for each resolver, support wildcard "identities" (e.g. * for appid, * for userId, * for certificate subject).
	// A more specific identity should take precedence over a wildcard.
	// TODO: Support wildcard operation names.
	// A more specific operation name should take precedence over a wildcard.
	// 1. Is there a matching identity?
	// 2. Is there a matching operation name for the matched identity?
	// 3. Is there a wildcard operation name for the matched identity?
	// 4. Is there a wildcard identity?
	// 5. Is there a matching operation name for the wildcard identity?
	// 6. Is there a wildcard operation name for the wildcard identity?
	// Ensure all lookups are still hash based for efficiency.
	// Reduce code duplication as much as possible.
	public static class RateLimiterResolvers
	{
		public const string OperationNameKey = "__RateLimiting__OperationName";
		public const string IdentitiesKey = "__RateLimiting__Identities";

		private static ILogger GetLogger(this HttpContext context, [CallerMemberName] string memberName = null)
		{
			var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger(nameof(RateLimiterResolvers));
			logger.LogInformation($"{memberName}: Starting rate limit resolver.");

			return logger;
		}

		public static RateLimitPartition<string> ResolveCertificateNameLimiter(HttpContext httpContext)
		{
			var logger = httpContext.GetLogger();
			var options = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled && httpContext.Items.TryGetValue(OperationNameKey, out var operationNameObj))
			{
				var operationName = operationNameObj.ToString();
				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true, AuthenticationType: "Certificate" } identity && identity.FindFirst("certificate-subject")?.Value is { Length: > 0 } subject)
				{
					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Found client certificate with subject '{subject}'.");
					if (options.CurrentValue.Policies.TryGetValue(subject, out var policy))
					{
						if (policy.TryGetValue(operationName, out var rule))
						{
							logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Client certificate with subject '{subject}' policy found. OperationName: '{operationName}' Limit: '{rule.Limit}' Window '{rule.Window}'");
							((HashSet<string>)httpContext.Items[IdentitiesKey]).Add(subject);

							var key = rule.CreatePartitionKey(subject, operationName);
							return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = rule.Limit,
								Window = rule.Window
							});
						}
					}

					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: No client certificate policy found.");
				}
				else
				{
					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: No client certificate found.");
				}
			}
			else
			{
				logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Rate limiting is not enabled.");
			}

			// Else no limit.
			return RateLimitPartition.GetNoLimiter(string.Empty);
		}

		public static RateLimitPartition<string> ResolveAppIdLimiter(HttpContext httpContext)
		{
			var logger = httpContext.GetLogger();
			var options = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled && httpContext.Items.TryGetValue(OperationNameKey, out var operationNameObj))
			{
				var operationName = operationNameObj.ToString();
				string appId = null;
				// NOTE: not checking authentication type because appId can come from either Certificate or S2SAuthentication.
				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
				{
					logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: Found authenticated identity, searching claims for appid.");
					appId = identity.FindFirst("appid")?.Value;
				}

				if (!string.IsNullOrWhiteSpace(appId))
				{
					var policyKey = $"AppId={appId}";
					if (options.CurrentValue.Policies.TryGetValue(policyKey, out var policy))
					{
						if (policy.TryGetValue(operationName, out var rule))
						{
							logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: appid value '{appId}' policy found. OperationName: '{operationName}' Limit: '{rule.Limit}' Window '{rule.Window}'");
							((HashSet<string>)httpContext.Items[IdentitiesKey]).Add(policyKey);

							var key = rule.CreatePartitionKey(appId, operationName);
							return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = rule.Limit,
								Window = rule.Window
							});
						}
					}

					logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: No appid policy found.");
				}
				else
				{
					logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: No appid found.");
				}
			}
			else
			{
				logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: Rate limiting is not enabled.");
			}

			// Else no limit.
			return RateLimitPartition.GetNoLimiter(string.Empty);
		}

		public static RateLimitPartition<string> ResolveUserIdLimiter(HttpContext httpContext)
		{
			var logger = httpContext.GetLogger();
			var options = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled && httpContext.Items.TryGetValue(OperationNameKey, out var operationNameObj))
			{
				var operationName = operationNameObj.ToString();
				string objectId = null;
				string tenantId = null;

				// NOTE: not checking authentication type because userId can come from either Certificate or S2SAuthentication.
				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
				{
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found authenticated identity, searching claims for TenantId and ObjectId.");
					tenantId = identity.FindFirst("x-ms-client-tenant-id")?.Value;
					objectId = identity.FindFirst("x-ms-client-object-id")?.Value;
				}

				if (!string.IsNullOrWhiteSpace(objectId) && !string.IsNullOrWhiteSpace(tenantId))
				{
					var userId = $"{tenantId}_{objectId}";
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found TenantId and ObjectId claims to form userId value '{userId}'.");
					var policyKey = $"UserId={userId}";
					if (options.CurrentValue.Policies.TryGetValue(policyKey, out var policy))
					{
						if (policy.TryGetValue(operationName, out var rule))
						{
							logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: UserId value '{userId}' policy found. OperationName: ' {operationName}' Limit: '{rule.Limit}' Window '{rule.Window}'");
							((HashSet<string>)httpContext.Items[IdentitiesKey]).Add(policyKey);

							var key = rule.CreatePartitionKey(userId, operationName);
							return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = rule.Limit,
								Window = rule.Window
							});
						}
					}

					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: No user id policy found.");
				}
				else
				{
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: No user id found.");
				}
			}
            else
            {
				logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Rate limiting is not enabled.");
            }

            // Else no match.
            return RateLimitPartition.GetNoLimiter(string.Empty);
		}
	}
}
