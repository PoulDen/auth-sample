import { BadRequestException, createParamDecorator, ExecutionContext } from '@nestjs/common';

export const BearerAuthToken = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest() as unknown as {
    headers?: { authorization?: unknown };
  };
  const auth = request.headers?.authorization;
  if (typeof auth === 'string') {
    if (auth.startsWith('Bearer ')) {
      return auth.replace('Bearer ', '');
    }
  }
  throw new BadRequestException('authorization header must be a bearer token');
});
