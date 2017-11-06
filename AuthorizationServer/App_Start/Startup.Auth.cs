using Constants;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace AuthorizationServer
{
    public partial class Startup
    {

        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable Application Sign In Cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Application",//用户登陆Authorization Server后的登陆凭证的标记名（Cookie）
                AuthenticationMode = AuthenticationMode.Passive,
                LoginPath = new PathString(Paths.LoginPath),
                LogoutPath = new PathString(Paths.LogoutPath),
            });

            // Enable External Sign In Cookie
            app.SetDefaultSignInAsAuthenticationType("External");
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "External",
                AuthenticationMode = AuthenticationMode.Passive,
                CookieName = CookieAuthenticationDefaults.CookiePrefix + "External",
                ExpireTimeSpan = TimeSpan.FromMinutes(5),
            });

            // Enable google authentication
            app.UseGoogleAuthentication();

            // Setup Authorization Server
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {

                //重写了MatchEndpoint（或设置了OnMatchEndpoint）后，我推荐注释掉这两行赋值语句
                AuthorizeEndpointPath = new PathString(Paths.AuthorizePath),
                TokenEndpointPath = new PathString(Paths.TokenPath),

                ApplicationCanDisplayErrors = true,
#if DEBUG
                AllowInsecureHttp = true,//这里的设置包含整个流程通信环境是否启用ssl
                                         //AllowInsecureHttp设置整个通信环境是否启用ssl,
                //不仅是OAuth服务端，也包含Client端（当设置为false时，若登记的Client端重定向url未采用https
#endif
                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthAuthorizationServerProvider
                {
                    ////验证Client的重定向Url，这个是为了安全,防钓鱼
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,

                    //验证Client的身份（ClientId以及ClientSecret）
                    OnValidateClientAuthentication = ValidateClientAuthentication,

                    
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials,
                    OnGrantClientCredentials = GrantClientCredetails
                },

                // Authorization code provider which creates and receives authorization code
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode,
                },

                // Refresh token provider which creates and receives referesh token
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken,
                }
            });
        }

        /// <summary>
        /// //验证重定向url的
        /// </summary>
        /// 这里context.ClientId是OAuth2处理流程上下文中获取的ClientId，
        /// 而Clients.Client1.Id是前面说的Constants项目中预设的测试数据。
        /// 如果我们有Client的注册机制，
        /// 那么Clients.Client1.Id对应的Clients.Client1.RedirectUrl就可能是从数据库中读取的。
        /// 而数据库中读取的RedirectUrl则可以直接作为字符串参数传给context.Validated(RedirectUrl)。
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == Clients.Client1.Id)
            {
                context.Validated(Clients.Client1.RedirectUrl);
            }
            else if (context.ClientId == Clients.Client2.Id)
            {
                context.Validated(Clients.Client2.RedirectUrl);
            }
            return Task.FromResult(0);
        }

        /// <summary>
        /// 验证Client身份
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;

            //TryGetBasicCredentials：是指Client可以按照Basic身份验证的规则提交ClientId和ClientSecret
            //TryGetFormCredentials：是指Client可以把ClientId和ClientSecret放在Post请求的form表单中提交
            if (context.TryGetBasicCredentials(out clientId, out clientSecret) ||
                context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                if (clientId == Clients.Client1.Id && clientSecret == Clients.Client1.Secret)
                {
                    context.Validated();
                }
                else if (clientId == Clients.Client2.Id && clientSecret == Clients.Client2.Secret)
                {
                    context.Validated();
                }
            }
            return Task.FromResult(0);
        }

        private Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(new GenericIdentity(context.UserName, OAuthDefaults.AuthenticationType), context.Scope.Select(x => new Claim("urn:oauth:scope", x)));

            context.Validated(identity);

            return Task.FromResult(0);
        }

        private Task GrantClientCredetails(OAuthGrantClientCredentialsContext context)
        {
            var identity = new ClaimsIdentity(new GenericIdentity(context.ClientId, OAuthDefaults.AuthenticationType), context.Scope.Select(x => new Claim("urn:oauth:scope", x)));

            context.Validated(identity);

            return Task.FromResult(0);
        }


        //用ConcurrentDictionary是为了线程安全
        private readonly ConcurrentDictionary<string, string> _authenticationCodes =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            string value;
            //_authenticationCodes.TryRemove就是code是一次性的，验证一次后即删除了
            if (_authenticationCodes.TryRemove(context.Token, out value))
            {
                context.DeserializeTicket(value);
            }
        }

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        //这里处理RefreshToken的生成和接收，只是简单的调用Token的加密设置和解密的方法。
        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}