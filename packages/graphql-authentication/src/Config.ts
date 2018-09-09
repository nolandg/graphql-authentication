import * as Email from 'email-templates';
import { User } from './Adapter';
import { Context } from './utils';
import { GraphqlAuthenticationAdapter } from './Adapter';

export interface IGraphqlAuthenticationConfig {
  mailer?: Email;
  mailAppUrl?: string;
  secret: string;
  secretSalt: string;
  requiredConfirmedEmailForLogin?: boolean;
  hookInviteUserPostCreate?: (
    data: any,
    ctx: Context,
    user: User
  ) => Promise<any>;
  adapter: GraphqlAuthenticationAdapter;
  validatePassword?: (value: string) => boolean;
  tokenExchangeScheme: string;
  tokenCookieName: string;
}

export function graphqlAuthenticationConfig(
  options: IGraphqlAuthenticationConfig
) {
  const defaults = {
    requiredConfirmedEmailForLogin: false,
    validatePassword: value => value.length >= 8
  };
  if (!options.adapter) {
    throw new Error(
      'You forgot to add the `adapter` option to graphql-authentication!'
    );
  }
  return Object.assign(defaults, options);
}
