import { Strategy as PassportStrategy } from 'passport-strategy';
import { AuthenticateOptions } from 'passport';
import { Request } from 'express';
import { Issuer, Client, TokenSet } from 'openid-client';
declare module 'express-session' {
    interface SessionData {
        authParams: AuthParams;
        tokenSet: TokenSet;
        isLoggedIn: Boolean;
    }
}
export interface AuthParams {
    scope?: string;
    state?: string;
    nonce?: string;
    codeVerifier?: string;
    codeChallengeMethod?: string;
    originalUrl?: string;
}
export interface StrategyOptions {
    name?: string;
    authParams?: AuthParams;
    url: string;
    client_id: string;
    client_secret: string;
    redirect_uri: string;
}
export declare class Strategy extends PassportStrategy {
    name: string;
    authParams: AuthParams;
    client?: Client;
    issuer?: Issuer;
    url: string;
    client_id: string;
    client_secret: string;
    redirect_uri: string;
    constructor(options: StrategyOptions);
    authenticate(req: Request, options: AuthenticateOptions): void;
    success(user: any, info?: any): void;
    error(err: Error): void;
    redirect(url: string, status?: number): void;
    verify(): void;
}
