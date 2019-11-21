using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using ActiveLogin.Authentication.GrandId.Api;
using ActiveLogin.Authentication.GrandId.Api.Models;
using ActiveLogin.Authentication.GrandId.AspNetCore.Models;
using ActiveLogin.Authentication.GrandId.AspNetCore.Serialization;
using ActiveLogin.Identity.Swedish;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ActiveLogin.Authentication.GrandId.AspNetCore
{
    public class GrandIdAuthenticationHandler : RemoteAuthenticationHandler<GrandIdAuthenticationOptions>
    {
        private readonly ILogger<GrandIdAuthenticationHandler> _logger;

        private readonly IGrandIdApiClient _grandIdApiClient;
        private readonly IMemoryCache _memoryCache;

        public GrandIdAuthenticationHandler(
            IOptionsMonitor<GrandIdAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            ILogger<GrandIdAuthenticationHandler> logger,
            IGrandIdApiClient grandIdApiClient,
            IMemoryCache memoryCache
            )
            : base(options, loggerFactory, encoder, clock)
        {
            _logger = logger;
            _grandIdApiClient = grandIdApiClient;
            _memoryCache = memoryCache;
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var state = GetStateFromMemoryCache();
            if (state == null)
            {
                return HandleRequestResult.Fail("Invalid state cookie.");
            }

            DeleteFromCache(state.SessionId);

            var sessionId = Request.Query["grandidsession"];
            if (string.IsNullOrEmpty(sessionId))
            {
                return HandleRequestResult.Fail("Missing grandidsession from GrandID.");
            }

            try
            {
                var sessionResult = await _grandIdApiClient.GetSessionAsync(Options.GrandIdAuthenticateServiceKey, sessionId);

                var properties = state.AuthenticationProperties;
                var ticket = GetAuthenticationTicket(sessionResult, properties);
                _logger.GrandIdGetSessionSuccess(sessionResult.SessionId);

                return HandleRequestResult.Success(ticket);
            }
            catch (Exception ex)
            {
                _logger.GrandIdGetSessionFailure(sessionId, ex);

                return HandleRequestResult.Fail("Failed to get session from GrandID.");
            }
        }

        private AuthenticationTicket GetAuthenticationTicket(SessionStateResponse loginResult, AuthenticationProperties properties)
        {
            DateTimeOffset? expiresUtc = null;
            if (Options.TokenExpiresIn.HasValue)
            {
                expiresUtc = Clock.UtcNow.Add(Options.TokenExpiresIn.Value);
                properties.ExpiresUtc = expiresUtc;
            }

            var claims = Options.UseSiths ? GetSithsClaims(loginResult, expiresUtc) 
                : GetClaims(loginResult, expiresUtc);

            var identity = new ClaimsIdentity(claims, properties.Items.First(p => p.Key == "scheme").Value, GrandIdClaimTypes.Name, GrandIdClaimTypes.Role);
            var principal = new ClaimsPrincipal(identity);

            return new AuthenticationTicket(principal, properties, Scheme.Name);
        }

        private IEnumerable<Claim> GetClaims(SessionStateResponse loginResult, DateTimeOffset? expiresUtc)
        {
            var personalIdentityNumber = SwedishPersonalIdentityNumber.Parse(loginResult.UserAttributes.PersonalIdentityNumber);

            var claims = new List<Claim>
                {
                    new Claim(GrandIdClaimTypes.Subject, personalIdentityNumber.ToLongString()),
                    new Claim(GrandIdClaimTypes.Name, loginResult.UserAttributes.Name),
                    new Claim(GrandIdClaimTypes.FamilyName, loginResult.UserAttributes.Surname),
                    new Claim(GrandIdClaimTypes.GivenName, loginResult.UserAttributes.GivenName),
                    new Claim(GrandIdClaimTypes.SwedishPersonalIdentityNumber, personalIdentityNumber.ToShortString())
                };

            AddOptionalClaims(claims, personalIdentityNumber, expiresUtc);

            return claims;
        }

        private IEnumerable<Claim> GetSithsClaims(SessionStateResponse loginResult, DateTimeOffset? expiresUtc)
        {
            var claims = new List<Claim>
                {
                    new Claim(GrandIdClaimTypes.Subject, loginResult.UserName ?? loginResult.UserAttributes.PersonalIdentityNumber),
                    new Claim(GrandIdClaimTypes.HsaId, loginResult.UserName ?? ""),
                    new Claim(GrandIdClaimTypes.GrandIdSession, loginResult.SessionId),
                    new Claim(GrandIdClaimTypes.GivenName, loginResult.UserAttributes.GivenName),
                    new Claim(GrandIdClaimTypes.FamilyName, loginResult.UserAttributes.Surname),
                    new Claim(GrandIdClaimTypes.Email, loginResult.UserAttributes.Email ?? ""),
                    new Claim(GrandIdClaimTypes.ClientCertificateSerial, loginResult.UserAttributes.ClientCertificateSerial ?? ""),
                };
            return claims;
        }

        private void AddOptionalClaims(List<Claim> claims, SwedishPersonalIdentityNumber personalIdentityNumber, DateTimeOffset? expiresUtc)
        {
            if (expiresUtc.HasValue)
            {
                claims.Add(new Claim(GrandIdClaimTypes.Expires, JwtSerializer.GetExpires(expiresUtc.Value)));
            }

            if (Options.IssueAuthenticationMethodClaim)
            {
                claims.Add(new Claim(GrandIdClaimTypes.AuthenticationMethod, Options.AuthenticationMethodName));
            }

            if (Options.IssueIdentityProviderClaim)
            {
                claims.Add(new Claim(GrandIdClaimTypes.IdentityProvider, Options.IdentityProviderName));
            }

            if (Options.IssueGenderClaim)
            {
                var jwtGender = JwtSerializer.GetGender(personalIdentityNumber.GetGenderHint());
                if (!string.IsNullOrEmpty(jwtGender))
                {
                    claims.Add(new Claim(GrandIdClaimTypes.Gender, jwtGender));
                }
            }

            if (Options.IssueBirthdateClaim)
            {
                var jwtBirthdate = JwtSerializer.GetBirthdate(personalIdentityNumber.GetDateOfBirthHint());
                claims.Add(new Claim(GrandIdClaimTypes.Birthdate, jwtBirthdate));
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var absoluteReturnUrl = GetAbsoluteUrl(Options.CallbackPath);
            var swedishPersonalIdentityNumber = GetSwedishPersonalIdentityNumber(properties);
            try
            {
                var response = await _grandIdApiClient.FederatedLoginAsync(Options.GrandIdAuthenticateServiceKey, absoluteReturnUrl, swedishPersonalIdentityNumber?.ToLongString());
                AppendStateCookie(properties, response.SessionId);
                _logger.GrandIdAuthSuccess(Options.GrandIdAuthenticateServiceKey, absoluteReturnUrl, response.SessionId);
                Response.Redirect(response.RedirectUrl);
            }
            catch (Exception ex)
            {
                _logger.GrandIdAuthFailure(Options.GrandIdAuthenticateServiceKey, absoluteReturnUrl, ex);
                throw;
            }
        }

        private static SwedishPersonalIdentityNumber GetSwedishPersonalIdentityNumber(AuthenticationProperties properties)
        {
            if (properties.Items.TryGetValue(GrandIdAuthenticationConstants.AuthenticationPropertyItemSwedishPersonalIdentityNumber, out var swedishPersonalIdentityNumber))
            {
                if (!string.IsNullOrWhiteSpace(swedishPersonalIdentityNumber))
                {
                    return SwedishPersonalIdentityNumber.Parse(swedishPersonalIdentityNumber);
                }
            }

            return null;
        }

        private string GetAbsoluteUrl(string returnUrl)
        {
            var absoluteUri = $"{Request.Scheme}://{Request.Host.ToUriComponent()}{Request.PathBase.ToUriComponent()}";
            return absoluteUri + returnUrl;
        }

        private void AppendStateCookie(AuthenticationProperties properties, string sessionId)
        {
            var state = new GrandIdState(properties);
            state.SessionId = sessionId;
            _memoryCache.Set(sessionId, state, DateTimeOffset.Now.AddMinutes(15));
        }

        private GrandIdState GetStateFromMemoryCache()
        {
            if (Request.Query.TryGetValue("grandidsession", out var value))
            {
                if (_memoryCache.TryGetValue<GrandIdState>(value.ToString(), out var result))
                {
                    return result;
                }
            }
            return null;
        }

        private void DeleteFromCache(string sessionId)
        {
            _memoryCache.Remove(sessionId);
        }
    }
}