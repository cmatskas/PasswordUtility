using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
namespace PasswordUtility.Web.Models
{
    public class PasswordModel
    {
        public string PasswordRequest { get; set; }
        public string PasswordResult { get; set; }
        public bool UpperCase { get; set; }
        public int Length { get; set; }
        public bool Digits { get; set; }
        public bool SpecialCharacters { get; set; }
    }
}
