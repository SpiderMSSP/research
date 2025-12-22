const LocalStrategy = require('passport-local').Strategy;
const { User } = require('../models');

module.exports = function(passport) {
    // Local Strategy
    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    }, async (email, password, done) => {
        try {
            // Find user by email
            const user = await User.findOne({ where: { email: email.toLowerCase() } });

            if (!user) {
                return done(null, false, { message: 'No account found with that email' });
            }

            // Verify password
            const isMatch = await user.validPassword(password);

            if (!isMatch) {
                return done(null, false, { message: 'Incorrect password' });
            }

            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }));

    // Serialize user for session
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // Deserialize user from session
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findByPk(id, {
                attributes: ['id', 'username', 'email', 'role', 'avatarUrl']
            });
            done(null, user);
        } catch (error) {
            done(error, null);
        }
    });
};
