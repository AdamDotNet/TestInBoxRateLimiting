using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace TestInBoxRateLimiting
{
	public static class RateLimiterResolvers
	{
		public const string OperationNameKey = "__OperationName";

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
							logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Client certificate with subject '{subject}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");
							var key = rule.CreatePartitionKey(subject);
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
					if (options.CurrentValue.Policies.TryGetValue(appId, out var policy))
					{
						if (policy.TryGetValue(operationName, out var rule))
						{
							logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: appid value '{appId}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");

							var key = rule.CreatePartitionKey(appId);
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

				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true, AuthenticationType: "Certificate" } identity)
				{
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found authenticated identity, searching claims for TenantId and ObjectId.");
					tenantId = identity.FindFirst("x-ms-client-tenant-id")?.Value;
					objectId = identity.FindFirst("x-ms-client-object-id")?.Value;
				}

				if (!string.IsNullOrWhiteSpace(objectId) && !string.IsNullOrWhiteSpace(tenantId))
				{
					var userId = $"{tenantId}_{objectId}";
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found TenantId and ObjectId claims to form userId value '{userId}'.");
					if (options.CurrentValue.Policies.TryGetValue(userId, out var policy))
					{
						if (policy.TryGetValue(operationName, out var rule))
						{
							logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: UserId value '{userId}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");

							var key = rule.CreatePartitionKey(userId);
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
