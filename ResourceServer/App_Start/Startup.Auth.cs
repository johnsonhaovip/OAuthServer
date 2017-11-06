using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ResourceServer
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            //OAuthBearer中间件就是解密了AccessToken
            app.UseOAuthBearerAuthentication(new Microsoft.Owin.Security.OAuth.OAuthBearerAuthenticationOptions());
        }
    }
}