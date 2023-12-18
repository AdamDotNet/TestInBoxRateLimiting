using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;

namespace TestInBoxRateLimiting
{
	public static class RateLimiterResolvers
	{
		private static ILogger GetLogger(this HttpContext context, [CallerMemberName] string memberName = null)
		{
			var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger(nameof(RateLimiterResolvers));
			logger.LogInformation($"{memberName}: Starting rate limit resolver.");

			return logger;
		}

		private static bool IsPathMatch(HttpContext httpContext, string policyPath)
		{
			// Normalize * to .*? and ensure ends with $ to make it a valid regex.
			// Add $ so root paths don't match sub paths.
			var normalPath = policyPath.Replace(".*?", "*").Replace("*", ".*?").Replace("$", "") + "$";

			// Do not run the same regex within the same request.
			var key = $"__{nameof(IsPathMatch)}__{normalPath}";
			if (httpContext.Items.TryGetValue(key, out var result) && result is bool resultValue)
			{
				return resultValue;
			}

			// Make check and cache result for the request.
			resultValue = Regex.IsMatch(httpContext.Request.Path.Value, normalPath, RegexOptions.IgnoreCase);
			httpContext.Items.Add(key, resultValue);
			return resultValue;
		}

		public static RateLimitPartition<string> ResolveCertificateNameLimiter(HttpContext httpContext)
		{
			var logger = httpContext.GetLogger();
			var options = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true, AuthenticationType: "Certificate" } identity && identity.FindFirst("certificate-subject")?.Value is { Length: > 0 } subject)
				{
					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Found client certificate with subject '{subject}'.");

					// TODO: Service Extensions also checks if the certificate is defined in ICertificateRepository. This is so that the policy can be created by certificate name, and then matched by name here.
					// Can we just set the policy name to the certificate Subject instead to avoid that lookup?
					if (options.CurrentValue.Policies.TryGetValue(subject, out var policy) && policy.Type == RateLimitPolicyType.CertificateName)
					{
						foreach (var rule in policy.Rules)
						{
							if (httpContext.Request.Method.Equals(rule.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(httpContext, rule.Path))
							{
								logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Client certificate with subject '{subject}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");

								var key = $"{subject}__{rule.Method}__{rule.Path}";
								return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
								{
									AutoReplenishment = true,
									PermitLimit = rule.Limit,
									Window = rule.Window
								});
							}
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

			if (options.CurrentValue.IsEnabled)
			{
				string appId = null;
				// NOTE: not checking authentication type because appId can come from either Certificate or S2SAuthentication.
				if (httpContext.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
				{
					logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: Found authenticated identity, searching claims for appid.");
					appId = identity.FindFirst("appid")?.Value;
				}

				if (!string.IsNullOrWhiteSpace(appId))
				{
					if (options.CurrentValue.Policies.TryGetValue(appId, out var policy) && policy.Type == RateLimitPolicyType.AppId)
					{
						foreach (var rule in policy.Rules)
						{
							if (httpContext.Request.Method.Equals(rule.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(httpContext, rule.Path))
							{
								logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: appid value '{appId}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");

								var key = $"{appId}__{rule.Method}__{rule.Path}";
								return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
								{
									AutoReplenishment = true,
									PermitLimit = rule.Limit,
									Window = rule.Window
								});
							}
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

			if (options.CurrentValue.IsEnabled)
			{
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
					if (options.CurrentValue.Policies.TryGetValue(userId, out var policy) && policy.Type == RateLimitPolicyType.UserId)
					{
						foreach (var rule in policy.Rules)
						{
							if (httpContext.Request.Method.Equals(rule.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(httpContext, rule.Path))
							{
								logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: UserId value '{userId}' policy found. Method: '{rule.Method}' Path: '{rule.Path}' Limit: '{rule.Limit}' Window '{rule.Window}'");

								var key = $"{userId}__{rule.Method}__{rule.Path}";
								return RateLimitPartition.GetFixedWindowLimiter(key, key => new FixedWindowRateLimiterOptions
								{
									AutoReplenishment = true,
									PermitLimit = rule.Limit,
									Window = rule.Window
								});
							}
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
