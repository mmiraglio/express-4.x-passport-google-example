require('dotenv').config();

var express = require('express');
var passport = require('passport');
var Strategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');

const scopes = [
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/user.birthday.read'
];
// Configure the Google strategy for use by Passport.
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Google API on the user's
// behalf, along with the user's profile.  The function must invoke `done`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.
passport.use(new Strategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: '/return'
},
  function (accessToken, refreshToken, profile, done) {
    // In this example, the user's Google profile is supplied as the user
    // record.  In a production-quality application, the Google profile should
    // be associated with a user record in the application's database, which
    // allows for account linking and authentication with other identity
    // providers.
    return done(null, {
      profile: profile,
      token: accessToken,
      refreshToken: refreshToken
    });
  }));

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Google profile is serialized
// and deserialized.
passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (obj, done) {
  done(null, obj);
});


// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'something nobody knows', resave: true, saveUninitialized: true }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());


// Define routes.
app.get('/',
  function (req, res) {

    var p = req.user ? req.user.profile : null;
    res.render('home', { user: p });

  });

app.get('/login',
  function (req, res) {
    res.render('login');
  });

app.get('/login/google',
  passport.authenticate('google', { scope: scopes }));

app.get('/return',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect('/');
  });

app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  function (req, res) {

    /**
     * Create a new OAuth2 client
     */
    const oAuth2Client = new google.auth.OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      '/return');

    oAuth2Client.credentials = {
      access_token: req.user.token,
      refresh_token: req.user.refreshToken
    };

    const people = google.people({
      version: 'v1',
      auth: oAuth2Client,
    });

    // See documentation of personFields at
    // https://developers.google.com/people/api/rest/v1/people/get
    people.people.get({
      resourceName: 'people/me',
      personFields: 'birthdays',
    }).then(function (result) {
      console.log(result.data.birthdays);
      res.render('profile',
        {
          user: req.user.profile,
          birthdays: result.data.birthdays
        });
    });
  });

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is listening on port: ${PORT}`);
});