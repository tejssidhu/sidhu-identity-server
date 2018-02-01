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
                new Client {
                    ClientId = "phonebook",
                    ClientName = "Phonebook Application",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
						"role",
						"phonebookAPI.read",
						"phonebookAPI.write"
					},
					AllowAccessTokensViaBrowser = true,
					RedirectUris = new List<string> {"http://localhost:4200/signin-callback.html", "http://localhost:4200/silent-renew.html"},
					ClientSecrets = new List<Secret>
					{
						new Secret("secret1")
					},

					PostLogoutRedirectUris = new List<string> { "http://localhost:4200" }
                }
            };
	    }
    }
}
