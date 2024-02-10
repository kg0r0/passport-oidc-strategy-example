import { Strategy as PassportStrategy } from 'passport-strategy';
import { AuthenticateOptions } from 'passport'
import { Request } from 'express';
import { Issuer, Client, TokenSet, generators } from 'openid-client';
import { verify } from 'crypto';

declare module 'express-session' {
  export interface SessionData {
    authParams: AuthParams
    tokenSet: TokenSet
    isLoggedIn: Boolean
  }
}

export interface AuthParams {
  scope?: string
  state?: string
  nonce?: string
  codeVerifier?: string
  codeChallengeMethod?: string
  originalUrl?: string
}

export interface StrategyOptions {
  name?: string
  authParams?: AuthParams
  url: string
  client_id: string
  client_secret: string
  redirect_uri: string
}

export class Strategy extends PassportStrategy {
  name: string;
  authParams: AuthParams;
  client: Client;
  issuer?: Issuer;
  url: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  verify: Function

  constructor(options: StrategyOptions, verify: Function) {
    super();
    this.name = options.name || 'example';
    this.authParams = options.authParams || {};
    this.client_id = options.client_id;
    this.client_secret = options.client_secret;
    this.redirect_uri = options.redirect_uri;
    this.url = options.url;
    this.issuer = new Issuer({
      issuer: 'https://accounts.google.com',
      authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
      userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
      code_challenge_methods_supported: ['S256'],
    })
    this.client = new this.issuer.Client({
      client_id: this.client_id,
      client_secret: this.client_secret,
      redirect_uris: [this.redirect_uri],
      response_types: ['code'],
    });
    this.verify = verify;
  }

  authenticate(req: Request, options: AuthenticateOptions): void {
    (async () => {
      const verified = (err: any, user: any, info: any) => {
        if (err) {
          return this.error(err);
        }
        if (!user) {
          return this.fail(info);
        }
        this.success(user, info);
      }

      if (!req.session) {
        throw new Error('express-session is not configured')
      }

      if (req.session.isLoggedIn && req.session.tokenSet) {
        return this.success(req.session.tokenSet, {});
      }

      if (req.query.code && req.session.authParams) {
        const state = req.session.authParams.state;
        const codeVerifier = req.session.authParams.codeVerifier;
        const nonce = req.session.authParams.nonce;
        const params = this.client.callbackParams(req);
        const tokenSet = await this.client.callback(
          this.redirect_uri,
          params,
          {
            state,
            nonce,
            code_verifier: codeVerifier
          }
        )
        req.session.tokenSet = tokenSet;
        req.session.isLoggedIn = true;
        this.redirect(req.session.authParams.originalUrl!);
        return
      }
      const scope = 'openid'
      const nonce = generators.nonce();
      const state = generators.state();
      const codeVerifier = generators.codeVerifier();
      const codeChallenge = generators.codeChallenge(codeVerifier);
      req.session.authParams = {};
      req.session.authParams.scope = scope;
      req.session.authParams.nonce = nonce;
      req.session.authParams.state = state;
      req.session.authParams.codeVerifier = codeVerifier;
      req.session.authParams.codeChallengeMethod = 'S256';
      req.session.authParams.originalUrl = req.originalUrl;
      this.authParams = req.session.authParams
      const authorizationUrl = this.client.authorizationUrl({
        response_type: 'code',
        scope,
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      this.redirect(authorizationUrl);
      return
    })().catch((err) => {
      this.fail(500);
      return
    });
  }
}
