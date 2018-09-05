import { Prisma } from './generated/prisma';
import { GraphqlAuthenticationAdapter, ID } from 'graphql-authentication';
import gql from 'graphql-tag';

// Build query AST of fields required/expected by this package
const userQuery = gql`
  {
    id
    email
    password
    name
    inviteToken
    inviteAccepted
    emailConfirmed
    emailConfirmToken
    resetToken
    resetExpires
    deletedAt
    lastLogin
    joinedAt
  }
`;

export class GraphqlAuthenticationPrismaAdapter
  implements GraphqlAuthenticationAdapter {
  prismaContextName = 'db';

  constructor(options: { prismaContextName?: string } = {}) {
    if (options && options.prismaContextName) {
      this.prismaContextName = options.prismaContextName;
    }
  }

  private db(ctx: object) {
    const db: Prisma = ctx[this.prismaContextName];
    if (!db) {
      throw new Error(
        `The Prisma binding is not attached to the \`${
          this.prismaContextName
        }\` property on your context.`
      );
    }
    return db;
  }

  findUserById(ctx: object, id: ID, info?: any) {
    return this.db(ctx).query.user({ where: { id } }, info);
  }
  findUserByEmail(ctx: object, email: string, info?: any) {
    const query = userQuery;

    // Check if application requested any additional fields of the User object
    // or supplied any fragments.
    // If so, merge them in with the required above
    if (info) {
      query.definitions = query.definitions.filter(
        def => def.kind !== 'FragmentDefinition'
      );
      const requiredSelections = query.definitions[0].selectionSet.selections;
      const topLevelSelections =
        info.operation.selectionSet.selections[0].selectionSet.selections;
      const userSelections = topLevelSelections.find(
        s => s.name.value === 'user'
      );
      if (userSelections) {
        query.definitions[0].selectionSet.selections = [
          ...requiredSelections,
          ...userSelections.selectionSet.selections
        ];
      }

      if (info.fragments) {
        for (const fragmentName in info.fragments) {
          const fragment = info.fragments[fragmentName];
          query.definitions.push(fragment);
        }
      }
    }

    return this.db(ctx).query.user({ where: { email } }, query);
  }
  userExistsByEmail(ctx: object, email: string) {
    return this.db(ctx).exists.User({ email });
  }
  private createUser(ctx: object, data: any) {
    return this.db(ctx).mutation.createUser({
      data
    });
  }
  createUserBySignup(ctx: object, data: any) {
    return this.createUser(ctx, data);
  }
  createUserByInvite(ctx: object, data: any) {
    return this.createUser(ctx, data);
  }
  private updateUser(ctx: object, userId: ID, data: any) {
    return this.db(ctx).mutation.updateUser({
      where: { id: userId },
      data
    });
  }
  updateUserConfirmToken(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
  updateUserLastLogin(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
  updateUserPassword(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
  updateUserResetToken(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
  updateUserInfo(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
  updateUserCompleteInvite(ctx: object, userId: ID, data: any) {
    return this.updateUser(ctx, userId, data);
  }
}
