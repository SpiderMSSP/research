const express = require('express');
const router = express.Router();
const { Course, Chapter, Lab, Progress } = require('../models');
const { ensureAuthenticated, ensureCanEdit } = require('../middleware/auth');

// New lab form
router.get('/new', ensureCanEdit, async (req, res) => {
    try {
        const { chapterId } = req.query;
        const chapter = await Chapter.findByPk(chapterId, {
            include: [{ model: Course, as: 'course' }]
        });

        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        // Get the next order index
        const maxOrder = await Lab.max('orderIndex', {
            where: { chapterId }
        }) || 0;

        res.render('labs/new', {
            title: `Add Lab to ${chapter.title}`,
            chapter,
            course: chapter.course,
            nextOrderIndex: maxOrder + 1
        });
    } catch (error) {
        console.error('Error loading new lab form:', error);
        req.flash('error', 'Error loading form');
        res.redirect('/courses');
    }
});

// Create lab
router.post('/', ensureCanEdit, async (req, res) => {
    try {
        const {
            chapterId, title, description, difficulty,
            walkthrough, solution, hints, filesPath,
            orderIndex, estimatedMinutes, objectives,
            prerequisites, tools, flagFormat, flag
        } = req.body;

        const chapter = await Chapter.findByPk(chapterId);
        if (!chapter) {
            req.flash('error', 'Chapter not found');
            return res.redirect('/courses');
        }

        const lab = await Lab.create({
            chapterId,
            title,
            description,
            difficulty,
            walkthrough,
            solution,
            hints: hints ? hints.split('\n---\n').filter(h => h.trim()) : [],
            filesPath,
            orderIndex: parseInt(orderIndex) || 0,
            estimatedMinutes: parseInt(estimatedMinutes) || null,
            objectives: objectives ? objectives.split('\n').filter(o => o.trim()) : [],
            prerequisites: prerequisites ? prerequisites.split('\n').filter(p => p.trim()) : [],
            tools: tools ? tools.split(',').map(t => t.trim()) : [],
            flagFormat,
            flag
        });

        req.flash('success', 'Lab created successfully');
        res.redirect(`/labs/${lab.id}`);
    } catch (error) {
        console.error('Error creating lab:', error);
        req.flash('error', 'Error creating lab');
        res.redirect('/courses');
    }
});

// Show lab
router.get('/:id', async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id, {
            include: [{
                model: Chapter,
                as: 'chapter',
                include: [{ model: Course, as: 'course' }]
            }]
        });

        if (!lab) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        // Check course visibility
        if (!lab.chapter.course.isPublished && (!req.user || !req.user.canEditCourses())) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        // Get all labs in this chapter for navigation
        const allLabs = await Lab.findAll({
            where: { chapterId: lab.chapterId },
            order: [['orderIndex', 'ASC']],
            attributes: ['id', 'title', 'orderIndex']
        });

        const currentIndex = allLabs.findIndex(l => l.id === lab.id);
        const prevLab = currentIndex > 0 ? allLabs[currentIndex - 1] : null;
        const nextLab = currentIndex < allLabs.length - 1 ? allLabs[currentIndex + 1] : null;

        // Get progress if logged in
        let labProgress = null;
        let showSolution = false;

        if (req.user) {
            labProgress = await Progress.findOne({
                where: { userId: req.user.id, labId: lab.id }
            });

            // Mark as in progress if first time viewing
            if (!labProgress) {
                labProgress = await Progress.create({
                    userId: req.user.id,
                    labId: lab.id,
                    status: 'in_progress'
                });
            } else if (labProgress.status === 'not_started') {
                await labProgress.markInProgress();
            }

            // Show solution if completed
            showSolution = labProgress.status === 'completed';
        }

        res.render('labs/show', {
            title: lab.title,
            lab,
            chapter: lab.chapter,
            course: lab.chapter.course,
            allLabs,
            prevLab,
            nextLab,
            labProgress,
            showSolution
        });
    } catch (error) {
        console.error('Error loading lab:', error);
        req.flash('error', 'Error loading lab');
        res.redirect('/courses');
    }
});

// Edit lab form
router.get('/:id/edit', ensureCanEdit, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id, {
            include: [{
                model: Chapter,
                as: 'chapter',
                include: [{ model: Course, as: 'course' }]
            }]
        });

        if (!lab) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        res.render('labs/edit', {
            title: `Edit: ${lab.title}`,
            lab,
            chapter: lab.chapter,
            course: lab.chapter.course
        });
    } catch (error) {
        console.error('Error loading lab for edit:', error);
        req.flash('error', 'Error loading lab');
        res.redirect('/courses');
    }
});

// Update lab
router.put('/:id', ensureCanEdit, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id);

        if (!lab) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        const {
            title, description, difficulty,
            walkthrough, solution, hints, filesPath,
            orderIndex, estimatedMinutes, objectives,
            prerequisites, tools, flagFormat, flag
        } = req.body;

        await lab.update({
            title,
            description,
            difficulty,
            walkthrough,
            solution,
            hints: hints ? hints.split('\n---\n').filter(h => h.trim()) : [],
            filesPath,
            orderIndex: parseInt(orderIndex) || lab.orderIndex,
            estimatedMinutes: parseInt(estimatedMinutes) || null,
            objectives: objectives ? objectives.split('\n').filter(o => o.trim()) : [],
            prerequisites: prerequisites ? prerequisites.split('\n').filter(p => p.trim()) : [],
            tools: tools ? tools.split(',').map(t => t.trim()) : [],
            flagFormat,
            flag
        });

        req.flash('success', 'Lab updated successfully');
        res.redirect(`/labs/${lab.id}`);
    } catch (error) {
        console.error('Error updating lab:', error);
        req.flash('error', 'Error updating lab');
        res.redirect(`/labs/${req.params.id}/edit`);
    }
});

// Delete lab
router.delete('/:id', ensureCanEdit, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id, {
            include: [{ model: Chapter, as: 'chapter' }]
        });

        if (!lab) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        const chapterId = lab.chapterId;
        await lab.destroy();

        req.flash('success', 'Lab deleted');
        res.redirect(`/chapters/${chapterId}`);
    } catch (error) {
        console.error('Error deleting lab:', error);
        req.flash('error', 'Error deleting lab');
        res.redirect('/courses');
    }
});

// Get hint (AJAX)
router.post('/:id/hint', ensureAuthenticated, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id);
        if (!lab) {
            return res.status(404).json({ error: 'Lab not found' });
        }

        const progress = await Progress.getOrCreate(req.user.id, { labId: lab.id });

        // Reveal next hint
        if (progress.hintsUsed < lab.hints.length) {
            progress.hintsUsed += 1;
            await progress.save();

            res.json({
                success: true,
                hintNumber: progress.hintsUsed,
                hint: lab.hints[progress.hintsUsed - 1],
                hasMoreHints: progress.hintsUsed < lab.hints.length
            });
        } else {
            res.json({
                success: false,
                message: 'No more hints available'
            });
        }
    } catch (error) {
        console.error('Error getting hint:', error);
        res.status(500).json({ error: 'Error getting hint' });
    }
});

// Mark lab complete
router.post('/:id/complete', ensureAuthenticated, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id);
        if (!lab) {
            return res.status(404).json({ error: 'Lab not found' });
        }

        const progress = await Progress.getOrCreate(req.user.id, { labId: lab.id });
        await progress.markComplete();

        res.json({ success: true, status: 'completed' });
    } catch (error) {
        console.error('Error marking lab complete:', error);
        res.status(500).json({ error: 'Error updating progress' });
    }
});

// Check flag (CTF-style)
router.post('/:id/check-flag', ensureAuthenticated, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id);
        if (!lab) {
            return res.status(404).json({ error: 'Lab not found' });
        }

        const { flag } = req.body;
        const isCorrect = lab.checkFlag(flag);

        if (isCorrect === null) {
            return res.json({ success: false, message: 'No flag for this lab' });
        }

        if (isCorrect) {
            const progress = await Progress.getOrCreate(req.user.id, { labId: lab.id });
            await progress.markComplete();

            return res.json({ success: true, message: 'Correct! Lab completed!' });
        }

        res.json({ success: false, message: 'Incorrect flag, try again' });
    } catch (error) {
        console.error('Error checking flag:', error);
        res.status(500).json({ error: 'Error checking flag' });
    }
});

// Get solution (requires completion or reveal)
router.get('/:id/solution', ensureAuthenticated, async (req, res) => {
    try {
        const lab = await Lab.findByPk(req.params.id, {
            include: [{
                model: Chapter,
                as: 'chapter',
                include: [{ model: Course, as: 'course' }]
            }]
        });

        if (!lab) {
            req.flash('error', 'Lab not found');
            return res.redirect('/courses');
        }

        const progress = await Progress.findOne({
            where: { userId: req.user.id, labId: lab.id }
        });

        // Allow viewing if completed or if user is instructor/admin
        const canView = progress?.status === 'completed' || req.user.canEditCourses();

        res.render('labs/solution', {
            title: `Solution: ${lab.title}`,
            lab,
            chapter: lab.chapter,
            course: lab.chapter.course,
            canView
        });
    } catch (error) {
        console.error('Error loading solution:', error);
        req.flash('error', 'Error loading solution');
        res.redirect('/courses');
    }
});

module.exports = router;
