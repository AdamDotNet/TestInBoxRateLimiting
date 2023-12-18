namespace TestInBoxRateLimiting
{
	public class RateLimitOptions
	{
		public bool IsEnabled { get; set; }

        public bool EnableQuery1 { get; set; }

        public TimeSpan Query1Window { get; set; }

        public int Query1Limit { get; set; }

        public bool EnableQuery2 { get; set; }

        public Dictionary<string, RateLimitPolicy> Policies { get; set; }
    }

	public enum RateLimitPolicyType
	{
		CertificateName,
		AppId,
		UserId
	}

	public class RateLimitPolicy
	{
        public RateLimitPolicyType Type { get; set; }

		public IEnumerable<RateLimitPolicyRule> Rules { get; set; } = [];
    }

	// TODO: If instead of regex, we evaluated against OperationName instead of Method/Path, then we can remove the use of regex, and rules can be dictionary based for faster lookup.
	public class RateLimitPolicyRule
	{
		public string Method { get; set; }

		public string Path { get; set; }

		public int Limit { get; set; }

		public TimeSpan Window { get; set; }
	}
}
