using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Test;

namespace sidhu_identity_server
{
    internal class Users
    {
	    public static List<TestUser> Get()
	    {
		    return new List<TestUser> {
			    new TestUser {
				    SubjectId = "2B3B4D72-1C15-40E0-A05A-012B724950C3",
				    Username = "tej",
				    Password = "password",
				    Claims = new List<Claim> {
					    new Claim(JwtClaimTypes.Email, "tej@somewhere.com"),
					    new Claim(JwtClaimTypes.Role, "admin")
				    }
			    }
		    };
	    }
	}
}
