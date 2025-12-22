const express = require('express');
const router = express.Router();
const { Course, Chapter, Lab, Progress } = require('../models');
const { ensureAuthenticated, ensureCanEdit } = require('../middleware/auth');

// New chapter form
router.get('/new', ensureCanEdit, async (req, res) => {
    try {
        const { courseId } = req.query;
        const course = await Course.findByPk(courseId);

        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        // Get the next order index
        const maxOrder = await Chapter.max('orderIndex', {
            where: { courseId }
        }) || 0;

        res.render('chapters/new', {
            title: `Add Chapter to ${course.title}`,
            course,
            nextOrderIndex: maxOrder + 1
        });
    } catch (error) {
        console.error('Error loading new chapter form:', error);
        req.flash('error', 'Error loading form');
        res.redirect('/courses');
    }
});

// Create chapter
router.post('/', ensureCanEdit, async (req, res) => {
    try {
        const {
            courseId, title, content, orderIndex,
            storyContext, previouslySummary, learningObjectives,
            estimatedMinutes, videoUrl
        } = req.body;

        const course = await Course.findByPk(courseId);
        if (!course) {
            req.flash('error', 'Course not found');
            return res.redirect('/courses');
        }

        const chapter = await Chapter.create({
            courseId,
            title,
            content,
            orderIndex: parseInt(orderIndex) || 0,
            storyContext,
            previouslySummary,
            learningObjectives: learningObjectives
                ? learningObjectives.split('\n').filter(o => o.trim())
                : [],
            estimatedMinutes: parseInt(estimatedMinutes) || null,
            videoUrl
        });

        req.flash('success', 'Chapter created successfully');
        res.redirect(`/chapters/${chapter.id}`);
    } catch (error) {
        console.error('Error creating chapter:', error);
        req.flash('error', 'Error creating chapter');
        res.redirect('/courses');
    }
});

// Show chapter
router.get('/:id', async (req, res) => {
    try {
        const chapter = await Chapter.findByPk(req.params.id, {
            include: [{
                model: Course,
                as: 'course'
            }, {
                model: Lab,
                as: 'labs',
                order: [['orderIndex', 'ASC']]
            }]
        });

        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        // Check course visibility
        if (!chapter.course.isPublished && (!req.user || !req.user.canEditCourses())) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        // Get all chapters for navigation
        const allChapters = await Chapter.findAll({
            where: { courseId: chapter.courseId },
            order: [['orderIndex', 'ASC']],
            attributes: ['id', 'title', 'slug', 'orderIndex']
        });

        // Get next/previous chapters
        const currentIndex = allChapters.findIndex(c => c.id === chapter.id);
        const prevChapter = currentIndex > 0 ? allChapters[currentIndex - 1] : null;
        const nextChapter = currentIndex < allChapters.length - 1 ? allChapters[currentIndex + 1] : null;

        // Get progress if logged in
        let chapterProgress = null;
        let labProgress = {};

        if (req.user) {
            chapterProgress = await Progress.findOne({
                where: { userId: req.user.id, chapterId: chapter.id }
            });

            // Mark as in progress if first time viewing
            if (!chapterProgress) {
                chapterProgress = await Progress.create({
                    userId: req.user.id,
                    chapterId: chapter.id,
                    status: 'in_progress'
                });
            } else if (chapterProgress.status === 'not_started') {
                await chapterProgress.markInProgress();
            }

            // Get lab progress
            const labProgressRecords = await Progress.findAll({
                where: {
                    userId: req.user.id,
                    labId: chapter.labs.map(l => l.id)
                }
            });
            labProgressRecords.forEach(p => {
                labProgress[p.labId] = p;
            });
        }

        // Sort labs by orderIndex
        chapter.labs.sort((a, b) => a.orderIndex - b.orderIndex);

        res.render('chapters/show', {
            title: chapter.title,
            chapter,
            course: chapter.course,
            allChapters,
            prevChapter,
            nextChapter,
            chapterProgress,
            labProgress
        });
    } catch (error) {
        console.error('Error loading chapter:', error);
        req.flash('error', 'Error loading chapter');
        res.redirect('/courses');
    }
});

// Edit chapter form
router.get('/:id/edit', ensureCanEdit, async (req, res) => {
    try {
        const chapter = await Chapter.findByPk(req.params.id, {
            include: [{ model: Course, as: 'course' }]
        });

        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        res.render('chapters/edit', {
            title: `Edit: ${chapter.title}`,
            chapter,
            course: chapter.course
        });
    } catch (error) {
        console.error('Error loading chapter for edit:', error);
        req.flash('error', 'Error loading chapter');
        res.redirect('/courses');
    }
});

// Update chapter
router.put('/:id', ensureCanEdit, async (req, res) => {
    try {
        const chapter = await Chapter.findByPk(req.params.id, {
            include: [{ model: Course, as: 'course' }]
        });

        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        const {
            title, content, orderIndex,
            storyContext, previouslySummary, learningObjectives,
            estimatedMinutes, videoUrl
        } = req.body;

        await chapter.update({
            title,
            content,
            orderIndex: parseInt(orderIndex) || chapter.orderIndex,
            storyContext,
            previouslySummary,
            learningObjectives: learningObjectives
                ? learningObjectives.split('\n').filter(o => o.trim())
                : [],
            estimatedMinutes: parseInt(estimatedMinutes) || null,
            videoUrl
        });

        req.flash('success', 'Chapter updated successfully');
        res.redirect(`/chapters/${chapter.id}`);
    } catch (error) {
        console.error('Error updating chapter:', error);
        req.flash('error', 'Error updating chapter');
        res.redirect(`/chapters/${req.params.id}/edit`);
    }
});

// Delete chapter
router.delete('/:id', ensureCanEdit, async (req, res) => {
    try {
        const chapter = await Chapter.findByPk(req.params.id, {
            include: [{ model: Course, as: 'course' }]
        });

        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        const courseSlug = chapter.course.slug;
        await chapter.destroy();

        req.flash('success', 'Chapter deleted');
        res.redirect(`/courses/${courseSlug}`);
    } catch (error) {
        console.error('Error deleting chapter:', error);
        req.flash('error', 'Error deleting chapter');
        res.redirect('/courses');
    }
});

// Mark chapter complete
router.post('/:id/complete', ensureAuthenticated, async (req, res) => {
    try {
        const chapter = await Chapter.findByPk(req.params.id);
        if (!chapter) {
            return res.status(404).json({ error: 'Chapter not found' });
        }

        const progress = await Progress.getOrCreate(req.user.id, {
            chapterId: chapter.id
        });

        await progress.markComplete();

        res.json({ success: true, status: 'completed' });
    } catch (error) {
        console.error('Error marking chapter complete:', error);
        res.status(500).json({ error: 'Error updating progress' });
    }
});

module.exports = router;
