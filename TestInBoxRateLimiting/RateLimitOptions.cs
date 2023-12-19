namespace TestInBoxRateLimiting
{
	public class RateLimitOptions
	{
		public bool IsEnabled { get; set; }

		public Dictionary<string, Dictionary<string, RateLimitPolicyRule>> Policies { get; set; }
	}

	public class RateLimitPolicyRule
	{
		public int Limit { get; set; }

		public TimeSpan Window { get; set; }

		public string CreatePartitionKey(string identity, string operationName) => HashCode.Combine(identity, operationName, Limit, Window).ToString();
	}
}
