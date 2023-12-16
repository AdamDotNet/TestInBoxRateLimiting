namespace TestInBoxRateLimiting
{
	public class ArmErrorResponse
	{
		public ArmError Error { get; set; }
	}

	public class ArmError
	{
		public string Code { get; set; }

		public string Message { get; set; }
	}
}
