using System.Web;
using System.Web.Mvc;

namespace jaytwo.AspNet.ProviderDemo
{
	public class FilterConfig
	{
		public static void RegisterGlobalFilters(GlobalFilterCollection filters)
		{
			filters.Add(new HandleErrorAttribute());
		}
	}
}