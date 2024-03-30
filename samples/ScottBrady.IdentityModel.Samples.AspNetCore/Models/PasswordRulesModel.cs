using System.Collections.Generic;

namespace ScottBrady.IdentityModel.Samples.AspNetCore.Models;

public class PasswordRulesModel
{
    public string Message { get; set; }
    public IEnumerable<string> Errors { get; set; } = new List<string>();
    public string Password { get; set; }
}