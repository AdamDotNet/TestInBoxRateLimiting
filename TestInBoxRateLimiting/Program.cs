using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;

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
				.AddCertificate();

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
			app.UseRateLimiter();
			app.UseAuthentication();
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
