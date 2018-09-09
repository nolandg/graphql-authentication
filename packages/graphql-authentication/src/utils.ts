import * as jwt from 'jsonwebtoken';
import { IGraphqlAuthenticationConfig } from './Config';
import { ID } from './Adapter';

const cookie = require('cookie');

export interface Context {
  graphqlAuthentication: IGraphqlAuthenticationConfig;
  request?: any;
  response?: any;
  req?: any;
}

function _getUserIdFromCookie(ctx: Context): string {
  const request = ctx.req || ctx.request;
  if (!request.headers.cookie) return '';
  const cookieName = ctx.graphqlAuthentication.tokenCookieName;
  const insecureCookieName = `${cookieName}_insecure`;
  if (!cookieName)
    throw new Error(
      'You must pass tokenCookieName to graphqlAuthentication when using "cookie" as tokenExchangeScheme.'
    );

  const cookies = cookie.parse(request.headers.cookie || '');
  const cookieValue = cookies[cookieName];
  // 2-cookie system allows user to logout without hitting server
  const insecureCookieValue = cookies[insecureCookieName];

  if (!cookieValue || !insecureCookieValue) return '';
  if (cookieValue == insecureCookieValue) return '';

  const { userId } = jwt.verify(
    cookieValue,
    ctx.graphqlAuthentication.secret
  ) as {
    userId: ID;
  };
  const { userId: insecureUserId } = jwt.verify(
    insecureCookieValue,
    `${ctx.graphqlAuthentication.secret}${ctx.graphqlAuthentication.secretSalt}`
  ) as {
    userId: ID;
  };

  if (userId !== insecureUserId) return '';

  return userId;
}

function _getUserIdFromHeader(ctx: Context): string {
  const request = ctx.req || ctx.request;

  const Authorization = request.get('Authorization');
  if (Authorization) {
    const token = Authorization.replace('Bearer ', '');
    const { userId } = jwt.verify(token, ctx.graphqlAuthentication.secret) as {
      userId: ID;
    };
    return userId;
  }
  return '';
}

function _getUserId(ctx: Context): string {
  const scheme = ctx.graphqlAuthentication.tokenExchangeScheme;
  if (!scheme)
    throw new Error(
      'You must pass tokenExchangeScheme to graphqlAuthentication.'
    );

  if (scheme === 'header') return _getUserIdFromHeader(ctx);
  if (scheme === 'cookie') return _getUserIdFromCookie(ctx);

  throw new Error(
    `Unrecognized value "${scheme}" for tokenExchangeScheme passed to graphqlAuthentication`
  );
}

export function getUserId(ctx: Context): string {
  const userId = _getUserId(ctx);
  if (userId) {
    return userId;
  }
  throw new AuthError();
}

export function getUser(ctx: Context): Promise<any> {
  return ctx.graphqlAuthentication.adapter.findUserById(ctx, getUserId(ctx));
}

export class AuthError extends Error {
  constructor() {
    super('Not authorized');
  }
}

export function isAuthResolver(parent: any, args: any, ctx: Context) {
  return !!_getUserId(ctx);
}
