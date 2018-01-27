using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4;

namespace sidhu_identity_server
{
    internal class Clients
    {
	    public static IEnumerable<Client> Get()
	    {
		    return new List<Client>
		    {
			    new Client
			    {
				    ClientId = "oauthClient",
				    ClientName = "Example Client Credentials Client Application",
				    AllowedGrantTypes = GrantTypes.ClientCredentials,
				    ClientSecrets = new List<Secret>
				    {
					    new Secret("superSecretPassword".Sha256())
				    },
				    AllowedScopes = new List<string> {"customAPI.read"}
			    },
                new Client {
                    ClientId = "openIdConnectClient",
                    ClientName = "Example Implicit Client Application",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "role",
                        "customAPI.write"
                    },
                    RedirectUris = new List<string> {"https://localhost:44387/signin-oidc"},
                    PostLogoutRedirectUris = new List<string> { "https://localhost:44387" }
                }
            };
	    }
    }
}
