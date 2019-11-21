using ActiveLogin.Authentication.GrandId.Api;
using System;
using System.Collections.Generic;
using System.Text;

namespace ActiveLogin.Authentication.GrandId.AspNetCore
{
    public interface IGrandIdAuthenticationConfigurator
    {
        void SetHsaId(string hsaId);
    }
    class GrandIdAuthenticationConfigurator : IGrandIdAuthenticationConfigurator
    {
        private readonly IGrandIdApiClient _grandIdApiClient;
        public GrandIdAuthenticationConfigurator(IGrandIdApiClient grandIdApiClient)
        {
            _grandIdApiClient = grandIdApiClient;
        }
        public void SetHsaId(string hsaId)
        {
            _grandIdApiClient.SetHsaId(hsaId);
        }
    }
}
