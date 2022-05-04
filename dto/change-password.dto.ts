import { IsString } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  oldPassword: string;
  @IsString()
  newPassword: string;

  constructor(oldPassword: string, newPassword: string) {
    this.oldPassword = oldPassword;
    this.newPassword = newPassword;
  }
}
