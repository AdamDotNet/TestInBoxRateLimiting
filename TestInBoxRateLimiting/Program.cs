using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Net.Http.Headers;

namespace TestInBoxRateLimiting
{
	public class Program
	{
		public static void Main(string[] args)
		{
			var builder = WebApplication.CreateBuilder(args);

			builder.WebHost.ConfigureKestrel(options =>
			{
				options.ConfigureHttpsDefaults(https => https.ClientCertificateMode = ClientCertificateMode.AllowCertificate);
			});

			// Add options. to the container.
			builder.Services.Configure<RateLimitOptions>(builder.Configuration.GetSection("RateLimit"));
			// Dummy implementations of authentication, just used to test out creating RateLimitPartitions based on the request details.
			builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
				.AddCertificate(certOptions =>
				{
					certOptions.Events = new CertificateAuthenticationEvents
					{
						OnCertificateValidated = context =>
						{
							var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
							var logger = loggerFactory.CreateLogger("OnCertificateValidated");

							// NOTE: In our real apps, we have constants for header names.
							var userToken = context.Request.Headers["x-ms-arm-signed-user-token"].ToString();
							var objectId = context.Request.Headers["x-ms-client-object-id"].ToString();
							var tenantId = context.Request.Headers["x-ms-client-tenant-id"].ToString();
							var appId = context.Request.Headers["x-ms-client-app-id"].ToString();

							// If either tid or oid is missing from the header, then infer it from the user token.
							if (!string.IsNullOrWhiteSpace(userToken))
							{
								JwtSecurityToken token = null;
								if (string.IsNullOrWhiteSpace(objectId) || string.IsNullOrWhiteSpace(tenantId))
								{
									token = TryParseSecurityToken("x-ms-arm-signed-user-token", userToken, logger);
									objectId = token?.Claims?.FirstOrDefault(c => c.Type == "oid")?.Value ?? string.Empty;
									tenantId = token?.Claims?.FirstOrDefault(c => c.Type == "tid")?.Value ?? string.Empty;
								}

								if (string.IsNullOrWhiteSpace(appId))
								{
									token ??= TryParseSecurityToken("x-ms-arm-signed-user-token", userToken, logger);
									appId = token?.Claims?.FirstOrDefault(c => c.Type == "appid")?.Value ?? string.Empty;
								}
							}

							context.Principal = new ClaimsPrincipal(new ClaimsIdentity([
								new Claim("Accept-Language", context.Request.Headers["Accept-Language"].ToString()),
								new Claim("x-ms-client-object-id", objectId),
								new Claim("x-ms-client-tenant-id", tenantId),
								new Claim("x-ms-client-principal-id", context.Request.Headers["x-ms-client-principal-id"].ToString()),
								new Claim("x-ms-client-principal-name", context.Request.Headers["x-ms-client-principal-name"].ToString()),
								new Claim("certificate-subject", context.ClientCertificate.Subject),
								new Claim("appid", appId)
							], authenticationType: "Certificate"));

							context.Properties = new AuthenticationProperties();
							context.Success();
							return Task.CompletedTask;
						}
					};
				})
				.AddPolicyScheme("auto", "auto select authentication", options =>
				{
					options.ForwardDefaultSelector = context =>
					{
						if (context.Request.Headers.ContainsKey(HeaderNames.Authorization))
						{
							return "S2SAuthentication";
						}

						return CertificateAuthenticationDefaults.AuthenticationScheme;
					};
				})
				.AddBearerToken("S2SAuthentication", configure =>
				{
					configure.Events = new BearerTokenEvents
					{
						OnMessageReceived = context =>
						{
							var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
							var logger = loggerFactory.CreateLogger("S2SOnMessageReceived");

							context.Principal = new ClaimsPrincipal(new ClaimsIdentity("S2SAuthentication"));
							var identity = (ClaimsIdentity)context.Principal.Identity;
							identity.AddClaim(new Claim("x-ms-client-object-id", context.Request.Headers["x-ms-client-object-id"].ToString()));
							identity.AddClaim(new Claim("x-ms-client-tenant-id", context.Request.Headers["x-ms-client-tenant-id"].ToString()));

							if (context.HttpContext.Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorization) && AuthenticationHeaderValue.TryParse(authorization, out var parsedAuthorization))
							{
								if (identity.FindFirst(identity.NameClaimType) == null)
								{
									var securityToken = TryParseSecurityToken(HeaderNames.Authorization, parsedAuthorization.Parameter, logger);
									var appId = securityToken?.Claims?.FirstOrDefault(c => c.Type == "appid")?.Value ?? string.Empty;
									identity.AddClaim(new Claim(identity.NameClaimType, appId));
									identity.AddClaim(new Claim("appid", appId));
								}
							}

							context.Properties = new AuthenticationProperties();
							context.Success();
							return Task.CompletedTask;
						}
					};
				});

			// Add services to the container.
			builder.Services.AddControllers();

			// Add rate limiting.
			builder.Services.AddRateLimiter(rateLimitOptions =>
			{
				rateLimitOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
				rateLimitOptions.OnRejected = OnRejected;

				// Now create a rate limiter that can inspect the HttpContext to determine the key.
				rateLimitOptions.GlobalLimiter = PartitionedRateLimiter.CreateChained(
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveCertificateNameLimiter, StringComparer.OrdinalIgnoreCase),
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveAppIdLimiter, StringComparer.OrdinalIgnoreCase),
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveUserIdLimiter, StringComparer.OrdinalIgnoreCase));
			});

			var app = builder.Build();

			// Configure the HTTP request pipeline.
			app.Use((httpContext, next) =>
			{
				// Create stable operation Id.
				// TODO: Check if the one we already use in real apps happens early enough and can be reused as is.
				var operationName = $"{httpContext.Request.Method}_{httpContext.Request.Path.Value.TrimStart('/')}";
				foreach (var (_, value) in httpContext.Request.RouteValues)
				{
					operationName = operationName.Replace(value.ToString(), "");
				}

				operationName = operationName.Replace("//", "/");
				// TODO: we should probably have HttpContext extensions that abstracts away the casting and the key names everywhere.
				httpContext.Items.Add(RateLimiterResolvers.OperationNameKey, operationName);
				httpContext.Items.Add(RateLimiterResolvers.IdentitiesKey, new HashSet<string>());

				return next(httpContext);
			});
			app.UseAuthentication();
			app.UseRateLimiter();
			app.MapControllers();

			app.Run();
		}

		private static JwtSecurityToken TryParseSecurityToken(string source, string token, ILogger logger)
		{
			try
			{
				return new JwtSecurityToken(token);
			}
			catch (Exception ex)
			{
				logger.LogWarning(ex, $"Failed to parse incoming token from {source}: {ex}");
				return null;
			}
		}

		private static async ValueTask OnRejected(OnRejectedContext context, CancellationToken cancellationToken)
		{
			var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger(nameof(RateLimiterResolvers));

			var operationName = context.HttpContext.Items[RateLimiterResolvers.OperationNameKey] as string;
			var identities = context.HttpContext.Items[RateLimiterResolvers.IdentitiesKey] as HashSet<string>;
			logger.LogInformation($"Rate limited request '{operationName}'. Matched identities: {string.Join(", ", identities)}");

			if (!context.HttpContext.Response.HasStarted && context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
			{
				// If this needs to be x-ms-retry-after, we can easily.
				context.HttpContext.Response.Headers.RetryAfter = retryAfter.ToString();
				await context.HttpContext.Response.WriteAsJsonAsync(new ArmErrorResponse
				{
					Error = new ArmError
					{
						Code = "TooManyRequests",
						Message = $"Please try again after {retryAfter}."
					}
				}, cancellationToken: cancellationToken);
			}
		}
	}
}
