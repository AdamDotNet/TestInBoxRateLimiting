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
			builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
				.AddCertificate(certOptions =>
				{
					certOptions.Events = new CertificateAuthenticationEvents
					{
						OnCertificateValidated = certContext =>
						{
							var userToken = certContext.Request.Headers["x-ms-arm-signed-user-token"].ToString();
							var objectId = certContext.Request.Headers["x-ms-client-object-id"].ToString();
							var tenantId = certContext.Request.Headers["x-ms-client-tenant-id"].ToString();

							// If either tid or oid is missing from the header, then infer it from the user token.
							if (!string.IsNullOrWhiteSpace(userToken) && (string.IsNullOrWhiteSpace(objectId) || string.IsNullOrWhiteSpace(tenantId)))
							{
								var token = new JwtSecurityToken(userToken);
								objectId = token.Claims.FirstOrDefault(c => c.Type == "oid")?.Value ?? string.Empty;
								tenantId = token.Claims.FirstOrDefault(c => c.Type == "tid")?.Value ?? string.Empty;
							}

							certContext.Principal = new ClaimsPrincipal(new ClaimsIdentity([
								new Claim("Accept-Language", certContext.Request.Headers["Accept-Language"].ToString()),
								new Claim("x-ms-client-object-id", objectId),
								new Claim("x-ms-client-tenant-id", tenantId),
								new Claim("x-ms-client-principal-id", certContext.Request.Headers["x-ms-client-principal-id"].ToString()),
								new Claim("x-ms-client-principal-name", certContext.Request.Headers["x-ms-client-principal-name"].ToString()),
							]));

							certContext.Properties = new AuthenticationProperties();
							certContext.Success();
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
							context.Principal = new ClaimsPrincipal(new ClaimsIdentity("S2SAuthentication"));
							var identity = (ClaimsIdentity)context.Principal.Identity;

							if (context.HttpContext.Request.Headers.TryGetValue(HeaderNames.Authorization, out var authorization) && AuthenticationHeaderValue.TryParse(authorization, out var parsedAuthorization))
							{
								// TODO: Try/catch parsing the security token.
								var securityToken = new JwtSecurityToken(parsedAuthorization.Parameter);
								if (identity.FindFirst(identity.NameClaimType) == null)
								{
									var appId = securityToken.Claims.FirstOrDefault(c => c.Type == "appid")?.Value ?? string.Empty;
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
					// PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveQuery1Limiter, StringComparer.OrdinalIgnoreCase),
					// PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveQuery2Limiter, StringComparer.OrdinalIgnoreCase));
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveCertificateNameLimiter, StringComparer.OrdinalIgnoreCase),
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveArmAppIdLimiter, StringComparer.OrdinalIgnoreCase),
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveS2SAppIdLimiter, StringComparer.OrdinalIgnoreCase),
					PartitionedRateLimiter.Create<HttpContext, string>(RateLimiterResolvers.ResolveUserIdLimiter, StringComparer.OrdinalIgnoreCase));
			});

			var app = builder.Build();

			// Configure the HTTP request pipeline.
			app.UseAuthentication();
			app.UseRateLimiter();
			app.MapControllers();

			app.Run();
		}

		private static async ValueTask OnRejected(OnRejectedContext context, CancellationToken cancellationToken)
		{
			// TODO: What handy info does the context have to log?
			var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
			var logger = loggerFactory.CreateLogger(nameof(RateLimiterResolvers));
			// logger.LogInformation($"Rate limited request {context.Lease.}");

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
