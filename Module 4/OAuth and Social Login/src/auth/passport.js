


// auth/passport.js — Google OAuth strategy

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, nextId } = require('../data');

// Verify Google profile and find, link, or create a local user.
async function verifyCallback(accessToken, refreshToken, profile, done) {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // 1. Returning OAuth user: find by Google ID first.
    let user = users.find((u) => u.googleId === googleId);

    if (user) {
      return done(null, user);
    }

    // 2. Existing local account: find by email.
    user = users.find((u) => u.email === email);

    if (user) {
      // Reject unverified emails to prevent account takeover.
      if (profile._json.email_verified !== true) {
        return done(null, false);
      }

      // Link the existing account to this Google identity.
      user.googleId = googleId;

      return done(null, user);
    }

    // 3. No matching account: create a new member.
    const newUser = {
      id: nextId(),
      googleId: googleId,
      email: email,
      name: name,
      role: 'member',
    };

    users.push(newUser);

    return done(null, newUser);
  } catch (err) {
    return done(err);
  }
}

// Configure Google OAuth strategy.
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || 'test-client-id',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'test-client-secret',
      callbackURL: '/auth/google/callback',
    },
    verifyCallback,
  ),
);

// Export the callback so tests can call it directly.
module.exports = { passport, verifyCallback };

