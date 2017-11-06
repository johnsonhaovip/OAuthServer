using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace AuthorizationServer.Controllers
{
    public class OAuthController : Controller
    {
        public ActionResult Authorize()
        {
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            //判断授权用户是否登录
            var authentication = HttpContext.GetOwinContext().Authentication;
            var ticket = authentication.AuthenticateAsync("Application").Result;
            var identity = ticket != null ? ticket.Identity : null;
            if (identity == null)
            {
                //Application要和AuthorizationServer/Startup里面的AuthenticationType = "Application"匹配
                //否则登录的用户，到OAuth控制器里面还是会认为没有登陆
                authentication.Challenge("Application");
                return new HttpUnauthorizedResult();
            }
            //如果用户登陆，则这里的identity就会有值。
            var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');

            if (Request.HttpMethod == "POST")
            {
                //处理授权的逻辑:
                //Claims去哪儿了？有什么作用？
                //
                //其实Client访问ResourceServer的api接口的时候，除了AccessToken，不需要其他任何凭据。
                //那么ResourceServer是怎么识别出用户登陆名的呢？
                //关键就是claims -based identity 这套东西。
                //其实所有的claims都加密存进了AccessToken中，
                //而ResourceServer中的OAuthBearer中间件就是解密了AccessToken，
                //获取了这些claims。这也是为什么之前强调AccessToken绝对不能泄露，
                //对于ResourceServer来说，访问者拥有AccessToken，那么就是受信任的，
                //颁发AccessToken的机构也是受信任的，所以对于AccessToken中加密的内容也是绝对相信的，
                //所以，ResourceServer这边甚至不需要再去数据库验证访问者Client的身份。

                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
                {
                    identity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("urn:oauth:scope", scope));
                    }
                    authentication.SignIn(identity);
                }
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Login")))
                {
                    authentication.SignOut("Application");
                    authentication.Challenge("Application");
                    return new HttpUnauthorizedResult();
                }
            }

            return View();
        }
    }
}