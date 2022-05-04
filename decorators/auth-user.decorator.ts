import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '../../users/entities/user.entity';

export const AuthUser = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest() as unknown as { user?: unknown };
  if (!(request.user instanceof User))
    throw new Error(`${request.user} is not an instance of User`);
  //request.headers.authorization
  return request.user;
});
