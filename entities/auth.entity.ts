import { IsInt, IsString } from 'class-validator';

export class TokenEntity {
  /**
   * Id of the authenticated user
   */
  @IsInt()
  public sub: number;

  /**
   * Time, which ths token was issued at, in seconds
   */
  @IsInt()
  public iat!: number;
  /**
   * Expiration time of this token, in seconds
   */
  @IsInt()
  public exp!: number;

  constructor(sub: number) {
    this.sub = sub;
  }
}

export class AuthEntity extends TokenEntity {
  /**
   * Hash of the associated refresh token
   */
  @IsString()
  public refreshHash: string;

  constructor(sub: number, refreshHash: string) {
    super(sub);
    this.refreshHash = refreshHash;
  }
}
