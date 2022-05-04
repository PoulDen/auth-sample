import { IsJWT } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AuthTokenDto {
  @ApiProperty()
  @IsJWT()
  public accessToken: string;

  constructor(access_token: string) {
    this.accessToken = access_token;
  }
}

export class RefreshTokenDto extends AuthTokenDto {
  @ApiProperty()
  @IsJWT()
  public refreshToken: string;

  constructor(access_token: string, refresh_token: string) {
    super(access_token);
    this.refreshToken = refresh_token;
  }
}
