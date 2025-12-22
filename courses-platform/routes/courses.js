const express = require('express');
const router = express.Router();
const { Course, Chapter, Lab, Progress, User } = require('../models');
const { ensureAuthenticated, ensureCanEdit } = require('../middleware/auth');
const slugify = require('slugify');

// List all courses
router.get('/', async (req, res) => {
    try {
        const whereClause = req.user?.canEditCourses() ? {} : { isPublished: true };

        const courses = await Course.findAll({
            where: whereClause,
            include: [{
                model: Chapter,
                as: 'chapters',
                attributes: ['id']
            }, {
                model: User,
                as: 'creator',
                attributes: ['id', 'username']
            }],
            order: [['orderIndex', 'ASC'], ['createdAt', 'DESC']]
        });

        // Calculate chapter counts
        const coursesWithCounts = courses.map(course => ({
            ...course.toJSON(),
            chapterCount: course.chapters.length
        }));

        res.render('courses/index', {
            title: 'Courses',
            courses: coursesWithCounts
        });
    } catch (error) {
        console.error('Error loading courses:', error);
        req.flash('error', 'Error loading courses');
        res.redirect('/');
    }
});

// New course form
router.get('/new', ensureCanEdit, (req, res) => {
    res.render('courses/new', { title: 'Create Course' });
});

// Create course
router.post('/', ensureCanEdit, async (req, res) => {
    try {
        const {
            title, description, shortDescription,
            difficulty, estimatedHours, tags,
            prerequisites, objectives
        } = req.body;

        const course = await Course.create({
            title,
            description,
            shortDescription,
            difficulty,
            estimatedHours: parseInt(estimatedHours) || null,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            prerequisites,
            objectives: objectives ? objectives.split('\n').filter(o => o.trim()) : [],
            createdBy: req.user.id
        });

        req.flash('success', 'Course created successfully');
        res.redirect(`/courses/${course.slug}`);
    } catch (error) {
        console.error('Error creating course:', error);
        req.flash('error', 'Error creating course');
        res.redirect('/courses/new');
    }
});

// Show single course
router.get('/:slug', async (req, res) => {
    try {
        const course = await Course.findOne({
            where: { slug: req.params.slug },
            include: [{
                model: Chapter,
                as: 'chapters',
                include: [{
                    model: Lab,
                    as: 'labs'
                }],
                order: [['orderIndex', 'ASC']]
            }, {
                model: User,
                as: 'creator',
                attributes: ['id', 'username', 'avatarUrl']
            }]
        });

        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        // Check if user can view unpublished course
        if (!course.isPublished && (!req.user || !req.user.canEditCourses())) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        // Get progress if user is logged in
        let progressMap = {};
        let courseProgress = 0;

        if (req.user) {
            const progress = await Progress.findAll({
                where: { userId: req.user.id }
            });

            progress.forEach(p => {
                if (p.chapterId) progressMap[`chapter_${p.chapterId}`] = p;
                if (p.labId) progressMap[`lab_${p.labId}`] = p;
            });

            courseProgress = await Progress.getCourseProgress(req.user.id, course.id);
        }

        // Sort chapters by orderIndex
        course.chapters.sort((a, b) => a.orderIndex - b.orderIndex);

        res.render('courses/show', {
            title: course.title,
            course,
            progressMap,
            courseProgress
        });
    } catch (error) {
        console.error('Error loading course:', error);
        req.flash('error', 'Error loading course');
        res.redirect('/courses');
    }
});

// Edit course form
router.get('/:slug/edit', ensureCanEdit, async (req, res) => {
    try {
        const course = await Course.findOne({ where: { slug: req.params.slug } });

        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        res.render('courses/edit', {
            title: `Edit: ${course.title}`,
            course
        });
    } catch (error) {
        console.error('Error loading course for edit:', error);
        req.flash('error', 'Error loading course');
        res.redirect('/courses');
    }
});

// Update course
router.put('/:slug', ensureCanEdit, async (req, res) => {
    try {
        const course = await Course.findOne({ where: { slug: req.params.slug } });

        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        const {
            title, description, shortDescription,
            difficulty, estimatedHours, tags,
            prerequisites, objectives, isPublished
        } = req.body;

        await course.update({
            title,
            description,
            shortDescription,
            difficulty,
            estimatedHours: parseInt(estimatedHours) || null,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            prerequisites,
            objectives: objectives ? objectives.split('\n').filter(o => o.trim()) : [],
            isPublished: isPublished === 'on'
        });

        req.flash('success', 'Course updated successfully');
        res.redirect(`/courses/${course.slug}`);
    } catch (error) {
        console.error('Error updating course:', error);
        req.flash('error', 'Error updating course');
        res.redirect(`/courses/${req.params.slug}/edit`);
    }
});

// Delete course
router.delete('/:slug', ensureCanEdit, async (req, res) => {
    try {
        const course = await Course.findOne({ where: { slug: req.params.slug } });

        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        await course.destroy();
        req.flash('success', 'Course deleted');
        res.redirect('/courses');
    } catch (error) {
        console.error('Error deleting course:', error);
        req.flash('error', 'Error deleting course');
        res.redirect('/courses');
    }
});

// Toggle publish status
router.post('/:slug/toggle-publish', ensureCanEdit, async (req, res) => {
    try {
        const course = await Course.findOne({ where: { slug: req.params.slug } });

        if (!course) {
            return res.status(404).json({ error: 'Course not found' });
        }

        await course.update({ isPublished: !course.isPublished });

        res.json({
            success: true,
            isPublished: course.isPublished
        });
    } catch (error) {
        console.error('Error toggling publish:', error);
        res.status(500).json({ error: 'Error updating course' });
    }
});

module.exports = router;
