import { Token } from '@prisma/client';

export class RefreshTokenEntity implements Token {
  hash: string;
  expiresAt: Date;
  userId: number;

  constructor(hash: string, expiresAt: Date, userId: number) {
    this.hash = hash;
    this.expiresAt = expiresAt;
    this.userId = userId;
  }
}
