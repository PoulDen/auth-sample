import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from '../users/users.controller';
import { UsersService } from '../users/users.service';
import { PrismaService } from '../prisma/prisma.service';
import { DeepMockProxy, mockDeep } from 'jest-mock-extended';
import { User } from '../users/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { instanceToPlain, plainToInstance } from 'class-transformer';
import { AuthUserDto } from './dto/auth-user.dto';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Config } from '../config';
import { mockConfig } from '../../test/test-utils';
import { Token } from '@prisma/client';
import { AuthTokenDto, RefreshTokenDto } from './dto/auth-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { AuthEntity, TokenEntity } from './entities/auth.entity';

describe('UsersController', () => {
  const userPassword = '12345678';
  const passwordHash = bcrypt.hashSync(userPassword, 5);

  const anotherPassword = '87654321';

  const lastTokenReset = new Date();
  const mockUser = (id: number): User => {
    return {
      id: id,
      username: `test${id}`,
      displayName: `test${id}_display`,
      passwordHash: passwordHash,
      admin: false,
      lastTokenReset: new Date(lastTokenReset),
    };
  };

  let service: AuthService;
  let prisma: DeepMockProxy<PrismaService>;
  let jwt: JwtService;

  const authUser = plainToInstance(User, mockUser(1));
  const adminUser = plainToInstance(User, mockUser(2));
  adminUser.admin = true;

  async function generateToken(
    user: User,
  ): Promise<{ tokenString: string; token: TokenEntity; hash: string }> {
    const tokenString = (await service.login(new AuthUserDto(user.username, userPassword)))
      .refreshToken;
    const token = plainToInstance(TokenEntity, jwt.decode(tokenString));
    const hash = await service.tokenHash(tokenString);
    await prisma.token.create({
      data: {
        hash: hash,
        userId: authUser.id,
        expiresAt: new Date(token.exp * 1000),
      },
    });
    return { tokenString: tokenString, token: token, hash: hash };
  }

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secretOrPrivateKey: 'secretKey',
          signOptions: {
            expiresIn: '15m',
          },
        }),
      ],
      controllers: [UsersController],
      providers: [
        UsersService,
        AuthService,
        { provide: ConfigService, useFactory: () => mockDeep<ConfigService>() },
        { provide: PrismaService, useFactory: () => mockDeep<PrismaService>() },
      ],
    }).compile();

    prisma = module.get<PrismaService>(PrismaService) as unknown as DeepMockProxy<PrismaService>;
    service = module.get<AuthService>(AuthService);
    jwt = module.get<JwtService>(JwtService);
    const config = module.get<ConfigService<Config>>(ConfigService) as unknown as DeepMockProxy<
      ConfigService<Config>
    >;
    mockConfig(config);

    prisma.user.findUnique.mockImplementation((async ({
      where,
    }: {
      where: { id: number; username: string };
    }) => {
      if (where.id === authUser.id || where.username === authUser.username) {
        return mockUser(authUser.id);
      } else if (where.id === adminUser.id || where.username === adminUser.username) {
        const user = mockUser(adminUser.id);
        user.admin = true;
        return user;
      }
      return null;
    }) as any);

    const tokens: Record<string, Token> = {};
    prisma.token.upsert.mockImplementation(((data: { create: unknown }) => {
      const token = data.create as Token;
      tokens[token.hash] = token;
      return data.create;
    }) as any);
    prisma.token.create.mockImplementation(((data: { data: unknown }) => {
      const token = data.data as Token;
      tokens[token.hash] = token;
      return data.data;
    }) as any);
    prisma.token.findUnique.mockImplementation(((data: { where: { hash: string } }) => {
      return tokens[data.where.hash] ?? null;
    }) as any);
    prisma.token.findMany.mockImplementation((() => {
      return Object.getOwnPropertyNames(tokens).map((k) => tokens[k]);
    }) as any);
  });

  it('Should be defined', () => {
    expect(service).toBeDefined();
  });

  it('Should login', async () => {
    await expect(
      service.login(new AuthUserDto(authUser.username, userPassword)),
    ).resolves.toBeInstanceOf(RefreshTokenDto);
  });

  describe('When validating user', () => {
    it('should return user for valid credentials', async () => {
      await expect(
        service.validateUser(new AuthUserDto(authUser.username, userPassword)),
      ).resolves.toEqual(authUser);
    });

    it('should return null for invalid credentials ', async () => {
      await expect(
        service.validateUser(new AuthUserDto(authUser.username, anotherPassword)),
      ).resolves.toBeNull();
    });
  });

  describe('When changing password', () => {
    it('should clear tokens for the user', async () => {
      await expect(
        service.changePassword(authUser, new ChangePasswordDto(userPassword, anotherPassword)),
      ).resolves.not.toThrow();
      expect(prisma.token.deleteMany).toHaveBeenCalledWith({
        where: {
          userId: authUser.id,
        },
      });
    });

    it('should throw BadRequestException for invalid new password', async () => {
      await expect(
        service.changePassword(authUser, new ChangePasswordDto(userPassword, '')),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(prisma.token.deleteMany).toHaveBeenCalledTimes(0);
    });

    it('should throw UnauthorizedException for invalid old password', async () => {
      await expect(
        service.changePassword(authUser, new ChangePasswordDto(anotherPassword, anotherPassword)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(prisma.token.deleteMany).toHaveBeenCalledTimes(0);
    });
  });

  describe('When logging out', () => {
    it('should delete refresh token associated with current access token', async () => {
      const hash = await service.tokenHash('token');
      const token = jwt.sign(instanceToPlain(new AuthEntity(authUser.id, hash)));
      await expect(service.logout(authUser, token)).resolves.not.toThrow();
      expect(prisma.token.delete).toHaveBeenCalledWith({
        where: {
          hash: hash,
        },
      });
    });
  });

  describe('When refreshing', () => {
    it('should return access token for valid refresh token', async () => {
      const token = await generateToken(authUser);
      await expect(service.refresh(authUser, token.tokenString)).resolves.toBeInstanceOf(
        AuthTokenDto,
      );
    });

    it('should throw ForbiddenException for invalid token', async () => {
      await expect(service.refresh(authUser, 'missingToken')).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('should throw ForbiddenException for expired token', async () => {
      jest.useFakeTimers();
      const token = await generateToken(authUser);

      try {
        jest.setSystemTime(token.token.exp * 1000 + 1000);
        await expect(service.refresh(authUser, token.tokenString)).rejects.toBeInstanceOf(
          ForbiddenException,
        );
      } finally {
        jest.useRealTimers();
      }
    });
  });

  describe('When validating refresh token', () => {
    it('should not throw for valid token', async () => {
      const token = await generateToken(authUser);
      await expect(service.validateRefreshToken(token.hash)).resolves.not.toThrow();
    });

    it('should throw ForbiddenException for invalid token', async () => {
      await expect(service.validateRefreshToken('missing hash')).rejects.toBeInstanceOf(
        ForbiddenException,
      );
    });

    it('should throw ForbiddenException for expired token', async () => {
      jest.useFakeTimers();
      const token = await generateToken(authUser);

      try {
        jest.setSystemTime(token.token.exp * 1000 + 1000);
        await expect(service.validateRefreshToken(token.hash)).rejects.toBeInstanceOf(
          ForbiddenException,
        );
      } finally {
        jest.useRealTimers();
      }
    });
  });

  describe('When validating refresh payload', () => {
    it('should return user for valid credentials', async () => {
      await expect(
        service.validatePayload(TokenEntity, {
          sub: 1,
          exp: (lastTokenReset.getTime() + 15000) / 1000,
          iat: lastTokenReset.getTime() / 1000,
        }),
      ).resolves.toEqual(authUser);
    });

    it('should throw UnauthorizedException for missing user', async () => {
      await expect(
        service.validatePayload(TokenEntity, {
          sub: 10,
          exp: (lastTokenReset.getTime() + 15000) / 1000,
          iat: lastTokenReset.getTime() / 1000,
        }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('should throw UnauthorizedException for token issued before last token reset', async () => {
      await expect(
        service.validatePayload(TokenEntity, {
          sub: 1,
          exp: (lastTokenReset.getTime() - 15000) / 1000,
          iat: (lastTokenReset.getTime() - 30000) / 1000,
        }),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });
});
