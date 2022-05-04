import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { User } from '../users/entities/user.entity';
import { AuthUserDto } from './dto/auth-user.dto';
import * as bcrypt from 'bcrypt';
import { AuthEntity, TokenEntity } from './entities/auth.entity';
import { AuthTokenDto, RefreshTokenDto } from './dto/auth-token.dto';
import { instanceToPlain, plainToInstance } from 'class-transformer';
import { PrismaService } from '../prisma/prisma.service';
import * as crypto from 'crypto';
import { Type } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Config } from '../config';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private config: ConfigService<Config>,
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async validateUser(userDto: AuthUserDto): Promise<User | null> {
    const user = await this.usersService.findOneByUsername(userDto.username);
    if (user && (await bcrypt.compare(userDto.password, user.passwordHash))) {
      return user;
    }
    return null;
  }

  /**
   * Returns refresh and access tokens for the given use Dto.<br>
   * User credentials are NOT validated in this method
   * @param userDto - user authorization DTO
   */
  async login(userDto: AuthUserDto): Promise<RefreshTokenDto> {
    const user = await this.usersService.findOneByUsername(userDto.username);
    const payload = instanceToPlain(new TokenEntity(user.id));

    const token = this.jwtService.sign(payload, {
      expiresIn: this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION_TIME'),
      secret: this.config.get<string>('JWT_REFRESH_TOKEN_SECRET'),
    });

    const hash = await this.tokenHash(token);
    const parsedToken = plainToInstance(TokenEntity, this.jwtService.decode(token));

    await this.prisma.token.upsert({
      where: {
        hash: hash,
      },
      update: {},
      create: {
        hash: hash,
        userId: user.id,
        expiresAt: new Date(parsedToken.exp * 1000),
      },
    });
    const authToken = await this.refresh(user, token);
    return new RefreshTokenDto(authToken.accessToken, token);
  }

  async changePassword(user: User, changePasswordDto: ChangePasswordDto): Promise<void> {
    const error = this.usersService.validatePassword(changePasswordDto.newPassword);
    if (error != null) {
      throw new BadRequestException(error);
    }
    if (!(await bcrypt.compare(changePasswordDto.oldPassword, user.passwordHash))) {
      throw new UnauthorizedException('Invalid old password');
    }
    await this.usersService.changePassword(user, changePasswordDto.newPassword);
    this.prisma.token.deleteMany({
      where: {
        userId: user.id,
      },
    });
  }

  async logout(user: User, rawToken: string): Promise<void> {
    const auth = plainToInstance(AuthEntity, this.jwtService.decode(rawToken));
    this.prisma.token.delete({
      where: {
        hash: auth.refreshHash,
      },
    });
  }

  async refresh(user: User, rawToken: string): Promise<AuthTokenDto> {
    const hash = await this.tokenHash(rawToken);
    await this.validateRefreshToken(hash);
    const payload = instanceToPlain(new AuthEntity(user.id, hash));
    return new AuthTokenDto(
      this.jwtService.sign(payload, {
        expiresIn: this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
        secret: this.config.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      }),
    );
  }

  async tokenHash(rawToken: string): Promise<string> {
    return crypto.createHash('sha256').update(rawToken).digest('base64');
  }

  async validateRefreshToken(tokenHash: string): Promise<void> {
    const token = await this.prisma.token.findUnique({
      where: {
        hash: tokenHash,
      },
    });
    if (token === null || Date.now() > token.expiresAt.getTime()) {
      throw new ForbiddenException('Refresh token was not found in valid refresh tokens list');
    }
  }

  async validatePayload<T extends TokenEntity>(
    InstanceType: Type<T>,
    payload: unknown,
  ): Promise<User> {
    const auth = plainToInstance(InstanceType, payload);
    let user;
    try {
      user = await this.usersService.findOne(auth.sub);
    } catch (e) {
      if (e instanceof NotFoundException) throw new UnauthorizedException("User can't be found");
      throw e;
    }
    if (user.lastTokenReset.getTime() / 1000 > auth.iat) {
      throw new UnauthorizedException('Token has been revoked');
    }
    return user;
  }
}
