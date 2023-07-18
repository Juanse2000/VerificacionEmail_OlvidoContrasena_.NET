using System.ComponentModel.DataAnnotations;

namespace VerifyEmailForgotPassword.Models
{
    public class ResetPasswordRequest
    {
        [Required]
        public string token { get; set; } = string.Empty;

        [Required, MinLength(6, ErrorMessage = "Por favor ingrese minimo 6 caracteres")]
        public string Password { get; set; } = string.Empty;

        [Required, Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
