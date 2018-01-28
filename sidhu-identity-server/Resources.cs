using System.Collections.Generic;
using IdentityServer4.Models;

namespace sidhu_identity_server
{
    internal class Resources
    {
	    public static IEnumerable<IdentityResource> GetIdentityResources()
	    {
		    return new List<IdentityResource> {
			    new IdentityResources.OpenId(),
			    new IdentityResources.Profile(),
			    new IdentityResources.Email(),
			    new IdentityResource {
				    Name = "role",
				    UserClaims = new List<string> {"role"}
			    }
		    };
	    }

	    public static IEnumerable<ApiResource> GetApiResources()
	    {
		    return new List<ApiResource> {
			    new ApiResource {
				    Name = "phonebookAPI",
				    DisplayName = "Phonebook API",
				    Description = "Phonebook API Access",
				    UserClaims = new List<string> {"role"},
				    ApiSecrets = new List<Secret> {new Secret("scopeSecret".Sha256())},
				    Scopes = new List<Scope> {
					    new Scope("phonebookAPI.read"),
					    new Scope("phonebookAPI.write")
				    }
			    }
		    };
	    }
	}
}
