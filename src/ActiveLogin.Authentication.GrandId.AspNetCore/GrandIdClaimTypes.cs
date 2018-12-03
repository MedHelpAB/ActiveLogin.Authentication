namespace ActiveLogin.Authentication.GrandId.AspNetCore
{
    public class GrandIdClaimTypes
    {
        public const string Role = "role";

        public const string Subject = "sub";
        public const string AuthenticationMethod = "amr";
        public const string IdentityProvider = "idp";
        public const string Expires = "exp";

        public const string Name = "name";
        public const string GivenName = "given_name";
        public const string FamilyName = "family_name";

        public const string Gender = "gender";
        public const string Birthdate = "birthdate";

        public const string HsaId = "hsaid";
        public const string GrandIdSession = "grandid_session";
        public const string ClientCertificateSerial = "client_serial";
        public const string Email = "email";

        public static string SwedishPersonalIdentityNumber = "swedish_personal_identity_number";

    }
}