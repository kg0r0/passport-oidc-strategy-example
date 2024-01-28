import express from 'express';
import passport from 'passport';
import session from 'express-session';
import crypto from 'crypto';
import { Strategy as ExampleStrategy } from '../../lib';
const app: express.Express = express()

declare module 'express-session' {
  export interface SessionData {
    passport: any;
  }
}

app.use(session({
  name: 'session',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: true,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, false);
});

passport.use(new ExampleStrategy({
  client_id: process.env.CLIENT_ID || '<CLIENT_ID>',
  client_secret: process.env.CLIENT_SECRET || '<CLIENT_SECRET>',
  url: 'https://accounts.google.com/.well-known/openid-configuration',
  redirect_uri: 'http://localhost:3000/cb',
}));

/**
 * routes
 */
app.get('/*',
  passport.authenticate('example', {}),
  (req: express.Request, res: express.Response) => {
    res.send(`Result: ${JSON.stringify(req.session.passport)}`);
    return
  }
);

app.listen(3000, () => {
  console.log('listen port: 3000');
});