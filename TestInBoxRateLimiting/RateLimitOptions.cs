namespace TestInBoxRateLimiting
{
	public class RateLimitOptions
	{
		public bool IsEnabled { get; set; }

		public Dictionary<string, Dictionary<string, RateLimitPolicyRule>> Policies { get; set; }
	}

	public class RateLimitPolicyRule
	{
		public string Method { get; set; }

		public string Path { get; set; }

		public int Limit { get; set; }

		public TimeSpan Window { get; set; }

		public string CreatePartitionKey(string key) => HashCode.Combine(key, Method, Path, Limit, Window).ToString();
	}
}
