require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const path = require('path');
const { marked } = require('marked');
const hljs = require('highlight.js');

const db = require('./models');
const configurePassport = require('./config/passport');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure marked for syntax highlighting
marked.setOptions({
    highlight: function(code, lang) {
        if (lang && hljs.getLanguage(lang)) {
            return hljs.highlight(code, { language: lang }).value;
        }
        return hljs.highlightAuto(code).value;
    },
    breaks: true,
    gfm: true
});

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));

// Session configuration
const sessionConfig = {
    store: new pgSession({
        conString: `postgres://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`,
        createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
};

app.use(session(sessionConfig));
app.use(flash());

// Passport configuration
configurePassport(passport);
app.use(passport.initialize());
app.use(passport.session());

// Global template variables
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    res.locals.marked = marked;
    next();
});

// Routes
app.use('/', require('./routes/auth'));
app.use('/courses', require('./routes/courses'));
app.use('/chapters', require('./routes/chapters'));
app.use('/labs', require('./routes/labs'));
app.use('/progress', require('./routes/progress'));

// Home page
app.get('/', async (req, res) => {
    try {
        const { Course, Chapter, Lab } = db;
        const courses = await Course.findAll({
            where: { isPublished: true },
            include: [{
                model: Chapter,
                include: [Lab]
            }],
            order: [['orderIndex', 'ASC']]
        });
        res.render('home', { courses });
    } catch (error) {
        console.error('Error loading home page:', error);
        res.render('home', { courses: [] });
    }
});

// Dashboard (requires auth)
app.get('/dashboard', require('./middleware/auth'), async (req, res) => {
    try {
        const { Course, Chapter, Lab, Progress } = db;

        const courses = await Course.findAll({
            include: [{
                model: Chapter,
                include: [Lab]
            }],
            order: [['orderIndex', 'ASC']]
        });

        const progress = await Progress.findAll({
            where: { userId: req.user.id }
        });

        // Calculate progress stats
        const progressMap = {};
        progress.forEach(p => {
            if (p.chapterId) progressMap[`chapter_${p.chapterId}`] = p;
            if (p.labId) progressMap[`lab_${p.labId}`] = p;
        });

        res.render('dashboard', { courses, progressMap });
    } catch (error) {
        console.error('Error loading dashboard:', error);
        req.flash('error', 'Error loading dashboard');
        res.redirect('/');
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).render('error', {
        message: 'Page not found',
        error: { status: 404 }
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).render('error', {
        message: err.message || 'Something went wrong',
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

// Database sync and server start
async function startServer() {
    try {
        await db.sequelize.authenticate();
        console.log('Database connected successfully');

        // Sync models (in development, use { alter: true } for updates)
        await db.sequelize.sync({ alter: process.env.NODE_ENV === 'development' });
        console.log('Database synced');

        // Create admin user if not exists
        const { User } = db;
        const adminExists = await User.findOne({ where: { role: 'admin' } });
        if (!adminExists && process.env.ADMIN_EMAIL) {
            await User.create({
                username: process.env.ADMIN_USERNAME || 'admin',
                email: process.env.ADMIN_EMAIL,
                password: process.env.ADMIN_PASSWORD || 'admin123',
                role: 'admin'
            });
            console.log('Admin user created');
        }

        app.listen(PORT, () => {
            console.log(`
╔═══════════════════════════════════════════════════════════════╗
║           COURSES PLATFORM - Security Research                ║
╠═══════════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                     ║
║  Environment: ${process.env.NODE_ENV || 'development'}                              ║
╚═══════════════════════════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
