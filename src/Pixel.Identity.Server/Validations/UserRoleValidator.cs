﻿using FluentValidation;
using Pixel.Identity.Shared.ViewModels;

namespace Pixel.Identity.Server.Validations
{
    public class UserRoleValidator : AbstractValidator<UserRoleViewModel>
    {
        public UserRoleValidator()
        {
            RuleFor(x => x.RoleName).NotEmpty().MinimumLength(4);           
        }
    }
}
