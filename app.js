var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');

const isDev = false;

require('dotenv').config({ path: isDev ? '.okta-dev.env' : '.okta.env' });
const { OKTA_DOMAIN, CLIENT_ID, CLIENT_SECRET } = process.env;

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'CanYouLookTheOtherWay',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());


// set up passport
passport.use('oidc', new Strategy(
  {
    issuer: `https://${OKTA_DOMAIN}${isDev ? '/oauth2/default' : ''}`,
    authorizationURL: `https://${OKTA_DOMAIN}/oauth2${isDev ? '/default' : ''}/v1/authorize`,
    tokenURL: `https://${OKTA_DOMAIN}/oauth2${isDev ? '/default' : ''}/v1/token`,
    userInfoURL: `https://${OKTA_DOMAIN}/oauth2${isDev ? '/default' : ''}/v1/userinfo`,

    clientID: `${CLIENT_ID}`,
    clientSecret: `${CLIENT_SECRET}`,
    callbackURL: 'http://localhost:3000/authorization-code/callback',
    scope: 'openid profile email groups'
  },
  // passport pass different args to verify() when it has different number of params
  // search for "arity == 10" in node_modules/passport-openidconnect/lib/strategy.js
  function verify (issuer, profile, context, idToken, accessToken, refreshToken, done) {
    // profile only has the baseline of the user info, it doesn't contain group claims
    // we can get groups claims from the idToken which is a JWT
    const payload = idToken.split('.')[1];

    const idTokenInfo = JSON.parse(new Buffer(payload, 'base64').toString());

    const groups = idTokenInfo.groups;

    console.log(111, issuer, profile, groups);

    return done(null, {
      ...profile,
      groups
    });
  })
);

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});


app.use('/', indexRouter);
app.use('/users', usersRouter);


app.use('/login', passport.authenticate('oidc'));

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.use('/profile', (req, res) => {
  console.log(2222, req.user);
  res.render('profile', { user: req.user });
});

app.post('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
