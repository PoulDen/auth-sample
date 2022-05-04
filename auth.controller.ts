import { Body, Controller, Get, Patch, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthUserDto } from './dto/auth-user.dto';
import { AuthTokenDto, RefreshTokenDto } from './dto/auth-token.dto';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { Public } from './decorators/public.decorator';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiOkResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { User } from '../users/entities/user.entity';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { UsersService } from '../users/users.service';
import { AuthUser } from './decorators/auth-user.decorator';
import { BearerAuthToken } from './decorators/auth-token.decorator';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ChangePasswordDto } from './dto/change-password.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private authService: AuthService, private usersService: UsersService) {}

  /**
   * Logs-in user with provided username and password.<br>
   * This endpoint creates new refresh token on every request. First auth token is also generated
   * and returned in the same response, but for refreshing access token you should use
   * /auth/refresh endpoint using refresh token instead of calling this endpoint again
   */
  @ApiCreatedResponse({
    description: 'Tokens were successfully created',
    type: RefreshTokenDto,
  })
  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Body()
    user: AuthUserDto,
  ): Promise<RefreshTokenDto> {
    return this.authService.login(user);
  }

  /**
   * Retrieves new access token with provided refresh token
   */
  @Public()
  @ApiBearerAuth()
  @UseGuards(JwtRefreshGuard)
  @ApiCreatedResponse({
    description: 'Access Token was created successfully',
    type: AuthTokenDto,
  })
  @ApiForbiddenResponse({
    description: 'Provided refresh token was not found in valid tokens list',
  })
  @Post('refresh')
  async refresh(@AuthUser() user: User, @BearerAuthToken() token: string): Promise<AuthTokenDto> {
    return this.authService.refresh(user, token);
  }

  /**
   * Registers a new user
   */
  @Public()
  @ApiCreatedResponse({
    description: 'The user has been successfully created',
    type: User,
  })
  @ApiConflictResponse({
    description: 'Username is already used by another user',
  })
  @Post('/register')
  register(@Body() createUserDto: CreateUserDto): Promise<User> {
    return this.usersService.create(createUserDto);
  }

  /**
   * Logs out current user from the system, invalidating refresh token of the current session
   */
  @Public()
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOkResponse({
    description: 'Logged out successfully',
  })
  @Get('/logout')
  logout(@AuthUser() user: User, @BearerAuthToken() token: string): Promise<void> {
    return this.authService.logout(user, token);
  }

  @Public()
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOkResponse({
    description: 'Password changed successfully',
  })
  @ApiBadRequestResponse({
    description: 'New password is invalid',
  })
  @ApiUnauthorizedResponse({
    description: 'Old password is invalid',
  })
  @Patch('/changePassword')
  changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @AuthUser() user: User,
  ): Promise<void> {
    return this.authService.changePassword(user, changePasswordDto);
  }
}
