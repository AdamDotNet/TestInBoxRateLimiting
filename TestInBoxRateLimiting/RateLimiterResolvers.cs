using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace TestInBoxRateLimiting
{
	public static class RateLimiterResolvers
	{
		private static ILogger GetLogger(this HttpContext context, [CallerMemberName] string memberName = null)
		{
			var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger(nameof(RateLimiterResolvers));
			logger.LogInformation($"Starting rate limit resolver {memberName}.");

			return logger;
		}

		// Test ones for easier verification.
		public static RateLimitPartition<string> ResolveQuery1Limiter(HttpContext context)
		{
			// YES, if options change to remove this policy, then the limiting stops.
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();
			if (options.CurrentValue.IsEnabled)
			{
				if (context.Request.Query.ContainsKey("query1"))
				{
					// YES, if options change, then we can change the permit limit and window, but it's not applied immediately.
					// Not sure what the delay is, but this factory DOES eventually get called again.
					return RateLimitPartition.GetFixedWindowLimiter("query1", key => new FixedWindowRateLimiterOptions
					{
						AutoReplenishment = true,
						PermitLimit = options.CurrentValue.Query1Limit,
						Window = options.CurrentValue.Query1Window
					});
				}
			}

			// Else no match or not enabled.
			return RateLimitPartition.GetNoLimiter(string.Empty);
		}

		public static RateLimitPartition<string> ResolveQuery2Limiter(HttpContext context)
		{
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();
			if (options.CurrentValue.IsEnabled)
			{
				if (context.Request.Query.ContainsKey("query2"))
				{
					return RateLimitPartition.GetFixedWindowLimiter("query2", key => new FixedWindowRateLimiterOptions
					{
						AutoReplenishment = true,
						PermitLimit = 2,
						Window = TimeSpan.FromSeconds(100)
					});
				}
			}

			// Else no match or not enabled.
			return RateLimitPartition.GetNoLimiter(string.Empty);
		}
		// END Test ones for easier verification.

		public static RateLimitPartition<string> ResolveCertificateNameLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				if (context.Connection.ClientCertificate?.Subject is { Length: > 0 } subject)
				{
					logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Found client certificate with subject '{subject}'.");

					// TODO: Service Extensions also checks if the certificate is defined in ICertificateRepository. This is so that the policy can be created by certificate name, and then matched by name here.
					if (options.CurrentValue.Policies.TryGetValue(subject, out var policy) && policy.Type == RateLimitPolicyType.CertificateName)
					{
						// TODO: Method and path verification. Idea, the path policy should be parsed into a regex and then matched against the request path.
						logger.LogInformation($"{nameof(ResolveCertificateNameLimiter)}: Client certificate with subject '{subject}' policy found. Limit: '{policy.Limit}' Window '{policy.Window}'");
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

		public static RateLimitPartition<string> ResolveArmAppIdLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				string appId = null;

				if (context.Request.Headers.TryGetValue("x-ms-client-app-id", out var clientAppIdValues))
				{
					appId = clientAppIdValues.ToString();
					logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: Found x-ms-client-app-id with value '{appId}'.");
				}
				else if (context.Request.Headers.TryGetValue("x-ms-arm-signed-user-token", out var armSignedUserTokenValues) && armSignedUserTokenValues.ToString() is { Length: > 0 } armSignedUserToken)
				{
					logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: Found x-ms-arm-signed-user-token, searching claims for appid.");
					var securityToken = new JwtSecurityToken(armSignedUserToken);
					if (securityToken.Claims.FirstOrDefault(c => c.Type.Equals("appid", StringComparison.OrdinalIgnoreCase)) is Claim appIdClaim)
					{
						appId = appIdClaim.Value;
						logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: Found appid claim from x-ms-arm-signed-user-token with value '{appId}'.");
					}
				}

				if (!string.IsNullOrWhiteSpace(appId))
				{
					if (options.CurrentValue.Policies.TryGetValue(appId, out var policy) && policy.Type == RateLimitPolicyType.AppId)
					{
						// TODO: Method and path verification. Idea, the path policy should be parsed into a regex and then matched against the request path.
						logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: appid value '{appId}' policy found. Limit: '{policy.Limit}' Window '{policy.Window}'");
						return RateLimitPartition.GetFixedWindowLimiter(appId, key => new FixedWindowRateLimiterOptions
						{
							AutoReplenishment = true,
							PermitLimit = policy.Limit,
							Window = policy.Window
						});
					}
					else
					{
						logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: No appid policy found.");
					}
				}
				else
				{
					logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: No appid found.");
				}
			}
			else
			{
				logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: Rate limiting is not enabled.");
			}

			// Else no limit.
			return RateLimitPartition.GetNoLimiter(string.Empty);
		}

		public static RateLimitPartition<string> ResolveS2SAppIdLimiter(HttpContext context)
		{
			var logger = context.GetLogger();
			var options = context.RequestServices.GetRequiredService<IOptionsMonitor<RateLimitOptions>>();

			if (options.CurrentValue.IsEnabled)
			{
				string appId = null;
				if (context.Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorizationValues) && authorizationValues.ToString() is { Length: > 0 } authorization)
				{
					logger.LogInformation($"{nameof(ResolveS2SAppIdLimiter)}: Found S2S authorization header, searching claims for appid.");
					if (AuthenticationHeaderValue.TryParse(authorization, out var parsedAuthorization) && !string.IsNullOrWhiteSpace(parsedAuthorization.Parameter))
					{
						var securityToken = new JwtSecurityToken(parsedAuthorization.Parameter);
						if (securityToken.Claims.FirstOrDefault(c => c.Type.Equals("appid", StringComparison.OrdinalIgnoreCase)) is Claim appIdClaim)
						{
							appId = appIdClaim.Value;
							logger.LogInformation($"{nameof(ResolveS2SAppIdLimiter)}: Found appid claim from S2S authorization header with value '{appId}'.");
						}
					}
				}

				if (!string.IsNullOrWhiteSpace(appId))
				{
					if (options.CurrentValue.Policies.TryGetValue(appId, out var policy) && policy.Type == RateLimitPolicyType.AppId)
					{
						// TODO: Method and path verification. Idea, the path policy should be parsed into a regex and then matched against the request path.
						logger.LogInformation($"{nameof(ResolveArmAppIdLimiter)}: appid value '{appId}' policy found. Limit: '{policy.Limit}' Window '{policy.Window}'");
						return RateLimitPartition.GetFixedWindowLimiter(appId, key => new FixedWindowRateLimiterOptions
						{
							AutoReplenishment = true,
							PermitLimit = policy.Limit,
							Window = policy.Window
						});
					}
					else
					{
						logger.LogInformation($"{nameof(ResolveS2SAppIdLimiter)}: No appid policy found.");
					}
				}
				else
				{
					logger.LogInformation($"{nameof(ResolveS2SAppIdLimiter)}: No appid found.");
				}
			}
			else
			{
				logger.LogInformation($"{nameof(ResolveS2SAppIdLimiter)}: Rate limiting is not enabled.");
			}

			// Else no match.
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

				logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Searching for x-ms-client-tenant-id and x-ms-client-object-id headers.");
				if (context.Request.Headers.TryGetValue("x-ms-client-tenant-id", out var clientTenantIdValues))
				{
					tenantId = clientTenantIdValues.ToString();
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found x-ms-client-tenant-id with value '{tenantId}'.");
				}

				if (context.Request.Headers.TryGetValue("x-ms-client-object-id", out var clientObjectIdValues))
				{
					objectId = clientObjectIdValues.ToString();
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found x-ms-client-object-id with value '{objectId}'.");
				}

				if (string.IsNullOrWhiteSpace(objectId) && string.IsNullOrWhiteSpace(tenantId))
				{
					logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: x-ms-client-tenant-id and x-ms-client-object-id headers not found. Searching for Authorization header.");
					if (context.Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorizationValues) && authorizationValues.ToString() is { Length: > 0 } authorization)
					{
						logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found Authorization header, searching claims for oid and tid.");
						if (AuthenticationHeaderValue.TryParse(authorization, out var parsedAuthorization) && !string.IsNullOrWhiteSpace(parsedAuthorization.Parameter))
						{
							var securityToken = new JwtSecurityToken(parsedAuthorization.Parameter);
							if (securityToken.Claims.FirstOrDefault(c => c.Type.Equals("oid", StringComparison.OrdinalIgnoreCase)) is Claim objectIdClaim)
							{
								objectId = objectIdClaim.Value;
								logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found oid claim from Authorization header with value '{objectId}'.");
							}

							if (securityToken.Claims.FirstOrDefault(c => c.Type.Equals("tid", StringComparison.OrdinalIgnoreCase)) is Claim tenantIdClaim)
							{
								tenantId = tenantIdClaim.Value;
								logger.LogInformation($"{nameof(ResolveUserIdLimiter)}: Found tid claim from Authorization header with value '{tenantId}'.");
							}
						}
					}
				}

				if (!string.IsNullOrWhiteSpace(objectId) && !string.IsNullOrWhiteSpace(tenantId))
				{
					var userId = $"{tenantId}_{objectId}";
					if (options.CurrentValue.Policies.TryGetValue(userId, out var policy) && policy.Type == RateLimitPolicyType.UserId)
					{
						// TODO: Method and path verification. Idea, the path policy should be parsed into a regex and then matched against the request path.
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
