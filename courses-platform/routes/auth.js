const express = require('express');
const router = express.Router();
const passport = require('passport');
const { User } = require('../models');
const { ensureGuest, ensureAuthenticated } = require('../middleware/auth');

// Login page
router.get('/login', ensureGuest, (req, res) => {
    res.render('auth/login', { title: 'Login' });
});

// Login action
router.post('/login', ensureGuest, (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
});

// Register page
router.get('/register', ensureGuest, (req, res) => {
    res.render('auth/register', { title: 'Register' });
});

// Register action
router.post('/register', ensureGuest, async (req, res) => {
    try {
        const { username, email, password, confirmPassword } = req.body;

        // Validation
        const errors = [];

        if (!username || username.length < 3) {
            errors.push('Username must be at least 3 characters');
        }

        if (!email || !email.includes('@')) {
            errors.push('Please enter a valid email');
        }

        if (!password || password.length < 6) {
            errors.push('Password must be at least 6 characters');
        }

        if (password !== confirmPassword) {
            errors.push('Passwords do not match');
        }

        if (errors.length > 0) {
            return res.render('auth/register', {
                title: 'Register',
                errors,
                username,
                email
            });
        }

        // Check if user exists
        const existingUser = await User.findOne({
            where: {
                [require('sequelize').Op.or]: [
                    { email: email.toLowerCase() },
                    { username: username.toLowerCase() }
                ]
            }
        });

        if (existingUser) {
            return res.render('auth/register', {
                title: 'Register',
                errors: ['An account with that email or username already exists'],
                username,
                email
            });
        }

        // Create user
        const user = await User.create({
            username,
            email: email.toLowerCase(),
            password
        });

        // Log in the user
        req.login(user, (err) => {
            if (err) {
                req.flash('error', 'Registration successful, please log in');
                return res.redirect('/login');
            }
            req.flash('success', 'Welcome! Your account has been created.');
            res.redirect('/dashboard');
        });

    } catch (error) {
        console.error('Registration error:', error);
        req.flash('error', 'An error occurred during registration');
        res.redirect('/register');
    }
});

// Logout
router.get('/logout', ensureAuthenticated, (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.flash('success', 'You have been logged out');
        res.redirect('/');
    });
});

// Profile page
router.get('/profile', ensureAuthenticated, async (req, res) => {
    const { Progress, Course, Chapter } = require('../models');

    const progress = await Progress.findAll({
        where: { userId: req.user.id, status: 'completed' }
    });

    res.render('auth/profile', {
        title: 'My Profile',
        completedCount: progress.length
    });
});

// Update profile
router.put('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const { username, bio } = req.body;

        await req.user.update({ username, bio });
        req.flash('success', 'Profile updated');
        res.redirect('/profile');
    } catch (error) {
        console.error('Profile update error:', error);
        req.flash('error', 'Error updating profile');
        res.redirect('/profile');
    }
});

module.exports = router;
