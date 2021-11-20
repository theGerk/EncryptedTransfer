using System;

internal static class Debug
{
	public static void WriteLine(object o)
	{
#if DEBUG
		Console.WriteLine(o);
#endif
	}
}
