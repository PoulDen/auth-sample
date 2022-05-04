import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { AuthEntity } from '../entities/auth.entity';
import { User } from '../../users/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { Config } from '../../config';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService, private configService: ConfigService<Config>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  async validate(payload: unknown): Promise<User> {
    await this.authService.validateRefreshToken((payload as AuthEntity).refreshHash);
    return this.authService.validatePayload(AuthEntity, payload);
  }
}
