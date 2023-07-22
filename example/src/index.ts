import express from 'express';
import passport from 'passport';
import session from 'express-session';
import crypto from 'crypto';
import { Strategy as ExampleStrategy } from '../../lib';
const app: express.Express = express()

passport.use(new ExampleStrategy({
  client_id: '<CLIENT_ID>',
  client_secret: '<CLIENT_SECRET>',
  url: 'https://accounts.google.com/.well-known/openid-configuration',
  redirect_uri: 'http://localhost:3000/cb',
}));

app.use(session({
  name: 'session',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: true,
  saveUninitialized: true
}));

/**
 * routes
 */
app.get('/*',
  passport.authenticate('example', {}),
  (req: express.Request, res: express.Response) => {
    res.send('OK');
  }
);

app.listen(3000, () => {
  console.log('listen port: 3000');
});