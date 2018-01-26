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
				    SubjectId = "f1e476e0-3d6e-489e-8cb3-cb41cd2e51c1",
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
