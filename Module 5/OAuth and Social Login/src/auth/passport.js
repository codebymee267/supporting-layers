
'use strict';

// auth/passport.js — Google OAuth strategy

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, nextId } = require('../data');

// Verify Google user and find or create an account
async function verifyCallback(accessToken, refreshToken, profile, done) {
  try {
    // Get details from Google profile
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // 1. Check if the Google user already exists
    const existingGoogleUser = users.find(
      (user) => user.googleId === googleId
    );

    if (existingGoogleUser) {
      return done(null, existingGoogleUser);
    }

    // 2. Check if a local account exists with the same email
    const existingUser = users.find(
      (user) => user.email === email
    );

    if (existingUser) {
      // Link account only if the Google email is verified
      if (profile._json.email_verified === true) {
        existingUser.googleId = googleId;
        return done(null, existingUser);
      }

      // Reject if email is not verified
      return done(null, false);
    }

    // 3. Create a new user if no account exists
    const newUser = {
      id: nextId(),
      googleId: googleId,
      email: email,
      name: name,
      role: 'member',
    };

    // Save new user
    users.push(newUser);

    return done(null, newUser);

  } catch (err) {
    // Handle unexpected errors
    return done(err);
  }
}

// Configure Google OAuth strategy
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

// Export passport and verifyCallback
module.exports = { passport, verifyCallback };
