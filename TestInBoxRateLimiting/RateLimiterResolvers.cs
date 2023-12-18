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

		private static bool IsPathMatch(string requestPath, string policyPath)
		{
			// Normalize * to .*? and ensure ends with $ to make it a valid regex.
			// Add $ so root paths don't match sub paths.
			var normalPath = policyPath.Replace(".*?", "*").Replace("*", ".*?").Replace("$", "") + "$";
			return Regex.IsMatch(requestPath, normalPath, RegexOptions.IgnoreCase);
		}

		public static RateLimitPartition<string> ResolveCertificateNameLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				if (context.User.Identity is ClaimsIdentity { IsAuthenticated: true, AuthenticationType: "Certificate" } identity && identity.FindFirst("certificate-subject")?.Value is { Length: > 0 } subject)
				{
					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Found client certificate with subject '{subject}'.");

					// TODO: Service Extensions also checks if the certificate is defined in ICertificateRepository. This is so that the policy can be created by certificate name, and then matched by name here.
					// Can we just set the policy name to the certificate Subject instead to avoid that lookup?
					if (options.CurrentValue.Policies.TryGetValue(subject, out var policy) && policy.Type == RateLimitPolicyType.CertificateName)
					{
						// TODO: A policy can't allow just one method/path combo.
						if (context.Request.Method.Equals(policy.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(context.Request.Path.Value, policy.Path))
						{
							logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Client certificate with subject '{subject}' policy found. Method: '{policy.Method}' Path: '{policy.Path}' Limit: '{policy.Limit}' Window '{policy.Window}'");
							return RateLimitPartition.GetFixedWindowLimiter(subject, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = policy.Limit,
								Window = policy.Window
							});
						}
						else
						{
							logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: No client certificate policy found.");
						}
					}
					else
					{
						logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: No client certificate policy found.");
					}
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

		public static RateLimitPartition<string> ResolveAppIdLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				string appId = null;
				// NOTE: not checking authentication type because appId can come from either Certificate or S2SAuthentication.
				if (context.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
				{
					logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: Found authenticated identity, searching claims for appid.");
					appId = identity.FindFirst("appid")?.Value;
				}

				if (!string.IsNullOrWhiteSpace(appId))
				{
					if (options.CurrentValue.Policies.TryGetValue(appId, out var policy) && policy.Type == RateLimitPolicyType.AppId)
					{
						// TODO: A policy can't allow just one method/path combo.
						if (context.Request.Method.Equals(policy.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(context.Request.Path.Value, policy.Path))
						{
							logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: appid value '{appId}' policy found. Method: '{policy.Method}' Path: '{policy.Path}' Limit: '{policy.Limit}' Window '{policy.Window}'");
							return RateLimitPartition.GetFixedWindowLimiter(appId, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = policy.Limit,
								Window = policy.Window
							});
						}
						else
						{
							logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: No appid policy found.");
						}
					}
					else
					{
						logger.LogInformation($"{nameof(ResolveAppIdLimiter)}: No appid policy found.");
					}
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

		public static RateLimitPartition<string> ResolveUserIdLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				string objectId = null;
				string tenantId = null;

				if (context.User.Identity is ClaimsIdentity { IsAuthenticated: true, AuthenticationType: "Certificate" } identity)
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
						// TODO: A policy can't allow just one method/path combo.
						if (context.Request.Method.Equals(policy.Method, StringComparison.OrdinalIgnoreCase) && IsPathMatch(context.Request.Path.Value, policy.Path))
						{
							logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: UserId value '{userId}' policy found. Limit: '{policy.Limit}' Window '{policy.Window}'");
							return RateLimitPartition.GetFixedWindowLimiter(userId, key => new FixedWindowRateLimiterOptions
							{
								AutoReplenishment = true,
								PermitLimit = policy.Limit,
								Window = policy.Window
							});
						}
						else
						{
							logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: No user id policy found.");
						}
					}
					else
					{
						logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: No user id policy found.");
					}
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
