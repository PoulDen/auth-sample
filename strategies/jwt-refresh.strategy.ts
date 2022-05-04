import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { User } from '../../users/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { Config } from '../../config';
import { AuthService } from '../auth.service';
import { TokenEntity } from '../entities/auth.entity';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh-token') {
  constructor(private authService: AuthService, private configService: ConfigService<Config>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
    });
  }

  async validate(payload: unknown): Promise<User> {
    return this.authService.validatePayload(TokenEntity, payload);
  }
}
