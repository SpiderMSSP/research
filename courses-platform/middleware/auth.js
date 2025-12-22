// Ensure user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash('error', 'Please log in to access this page');
    res.redirect('/login');
}

// Ensure user is NOT authenticated (for login/register pages)
function ensureGuest(req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    res.redirect('/dashboard');
}

// Ensure user can edit courses (instructor or admin)
function ensureCanEdit(req, res, next) {
    if (req.isAuthenticated() && req.user.canEditCourses()) {
        return next();
    }
    req.flash('error', 'You do not have permission to perform this action');
    res.redirect('/');
}

// Ensure user is admin
function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.isAdmin()) {
        return next();
    }
    req.flash('error', 'Admin access required');
    res.redirect('/');
}

// Optional auth - populates user if logged in but doesn't require it
function optionalAuth(req, res, next) {
    // User is already populated by passport if logged in
    next();
}

module.exports = ensureAuthenticated;
module.exports.ensureAuthenticated = ensureAuthenticated;
module.exports.ensureGuest = ensureGuest;
module.exports.ensureCanEdit = ensureCanEdit;
module.exports.ensureAdmin = ensureAdmin;
module.exports.optionalAuth = optionalAuth;
