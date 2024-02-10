"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Strategy = void 0;
const passport_strategy_1 = require("passport-strategy");
const openid_client_1 = require("openid-client");
class Strategy extends passport_strategy_1.Strategy {
    constructor(options, verify) {
        super();
        this.name = options.name || 'example';
        this.authParams = options.authParams || {};
        this.client_id = options.client_id;
        this.client_secret = options.client_secret;
        this.redirect_uri = options.redirect_uri;
        this.url = options.url;
        this.issuer = new openid_client_1.Issuer({
            issuer: 'https://accounts.google.com',
            authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
            token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
            userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
            code_challenge_methods_supported: ['S256'],
        });
        this.client = new this.issuer.Client({
            client_id: this.client_id,
            client_secret: this.client_secret,
            redirect_uris: [this.redirect_uri],
            response_types: ['code'],
        });
        this.verify = verify;
    }
    authenticate(req, options) {
        (() => __awaiter(this, void 0, void 0, function* () {
            const verified = (err, user, info) => {
                if (err) {
                    return this.error(err);
                }
                if (!user) {
                    return this.fail(info);
                }
                this.success(user, info);
            };
            if (!req.session) {
                throw new Error('express-session is not configured');
            }
            if (req.session.isLoggedIn && req.session.tokenSet) {
                return this.success(req.session.tokenSet, {});
            }
            if (req.query.code && req.session.authParams) {
                const state = req.session.authParams.state;
                const codeVerifier = req.session.authParams.codeVerifier;
                const nonce = req.session.authParams.nonce;
                const params = this.client.callbackParams(req);
                const tokenSet = yield this.client.callback(this.redirect_uri, params, {
                    state,
                    nonce,
                    code_verifier: codeVerifier
                });
                req.session.tokenSet = tokenSet;
                req.session.isLoggedIn = true;
                this.redirect(req.session.authParams.originalUrl);
                return;
            }
            const scope = 'openid';
            const nonce = openid_client_1.generators.nonce();
            const state = openid_client_1.generators.state();
            const codeVerifier = openid_client_1.generators.codeVerifier();
            const codeChallenge = openid_client_1.generators.codeChallenge(codeVerifier);
            req.session.authParams = {};
            req.session.authParams.scope = scope;
            req.session.authParams.nonce = nonce;
            req.session.authParams.state = state;
            req.session.authParams.codeVerifier = codeVerifier;
            req.session.authParams.codeChallengeMethod = 'S256';
            req.session.authParams.originalUrl = req.originalUrl;
            this.authParams = req.session.authParams;
            const authorizationUrl = this.client.authorizationUrl({
                response_type: 'code',
                scope,
                state,
                nonce,
                code_challenge: codeChallenge,
                code_challenge_method: 'S256',
            });
            this.redirect(authorizationUrl);
            return;
        }))().catch((err) => {
            this.fail(500);
            return;
        });
    }
}
exports.Strategy = Strategy;
