//this file needs to require Passport, the strategy, Mongoose and the User model
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = mongoose.model('User');


// For a local strategy, we essentially just need to write a Mongoose query on the User model.
//  This query should find a user with the email address specified,
//   and then call the validPassword method to see if the hashes match.

// There’s just one curiosity of Passport to deal with. Internally, 
// the local strategy for Passport expects two pieces of data called username and password. 
// However, we’re using email as our unique identifier, not username. 
// This can be configured in an options object with a usernameField property in the strategy definition.
//  After that, it’s over to the Mongoose query

passport.use(
    new LocalStrategy(
        {
            usernameField: 'email'
        },
        function (username, password, done) {
            User.findOne({ email: username }, function (err, user) {
                if (err) {
                    return done(err);
                }
                // Return if user not found in database
                if (!user) {
                    return done(null, false, {
                        message: 'User not found'
                    });
                }
                // Return if password is wrong
                if (!user.validPassword(password)) {
                    return done(null, false, {
                        message: 'Password is wrong'
                    });
                }
                // If credentials are correct, return the user object
                return done(null, user);
            });
        }
    )
);

// Note: how the validPassword schema method is called directly on the user instance.

// Now Passport just needs to be added to the application. 
// So in app.js we need to require the Passport module, 
// require the Passport config and initialize Passport as middleware.
//  The placement of all of these items inside app.js is quite important, 
//  as they need to fit into a certain sequence