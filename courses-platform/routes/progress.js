const express = require('express');
const router = express.Router();
const { Course, Chapter, Lab, Progress } = require('../models');
const { ensureAuthenticated } = require('../middleware/auth');

// Get user's overall progress
router.get('/', ensureAuthenticated, async (req, res) => {
    try {
        const courses = await Course.findAll({
            where: { isPublished: true },
            include: [{
                model: Chapter,
                as: 'chapters',
                include: [{ model: Lab, as: 'labs' }]
            }]
        });

        const progressData = [];

        for (const course of courses) {
            const courseProgress = await Progress.getCourseProgress(req.user.id, course.id);
            progressData.push({
                course,
                progress: courseProgress
            });
        }

        res.json({ success: true, data: progressData });
    } catch (error) {
        console.error('Error getting progress:', error);
        res.status(500).json({ error: 'Error getting progress' });
    }
});

// Get progress for a specific course
router.get('/course/:courseId', ensureAuthenticated, async (req, res) => {
    try {
        const { courseId } = req.params;

        const course = await Course.findByPk(courseId, {
            include: [{
                model: Chapter,
                as: 'chapters',
                include: [{ model: Lab, as: 'labs' }],
                order: [['orderIndex', 'ASC']]
            }]
        });

        if (!course) {
            return res.status(404).json({ error: 'Course not found' });
        }

        const chaptersProgress = [];

        for (const chapter of course.chapters) {
            const chapterProg = await Progress.findOne({
                where: { userId: req.user.id, chapterId: chapter.id }
            });

            const labsProgress = [];
            for (const lab of chapter.labs) {
                const labProg = await Progress.findOne({
                    where: { userId: req.user.id, labId: lab.id }
                });
                labsProgress.push({
                    labId: lab.id,
                    title: lab.title,
                    status: labProg?.status || 'not_started',
                    completedAt: labProg?.completedAt,
                    hintsUsed: labProg?.hintsUsed || 0
                });
            }

            chaptersProgress.push({
                chapterId: chapter.id,
                title: chapter.title,
                status: chapterProg?.status || 'not_started',
                completedAt: chapterProg?.completedAt,
                labs: labsProgress
            });
        }

        const overallProgress = await Progress.getCourseProgress(req.user.id, courseId);

        res.json({
            success: true,
            courseId,
            courseTitle: course.title,
            overallProgress,
            chapters: chaptersProgress
        });
    } catch (error) {
        console.error('Error getting course progress:', error);
        res.status(500).json({ error: 'Error getting progress' });
    }
});

// Update notes for a chapter or lab
router.put('/notes', ensureAuthenticated, async (req, res) => {
    try {
        const { chapterId, labId, notes } = req.body;

        if (!chapterId && !labId) {
            return res.status(400).json({ error: 'Must specify chapterId or labId' });
        }

        const progress = await Progress.getOrCreate(req.user.id, {
            chapterId: chapterId || null,
            labId: labId || null
        });

        await progress.update({ notes });

        res.json({ success: true, notes: progress.notes });
    } catch (error) {
        console.error('Error updating notes:', error);
        res.status(500).json({ error: 'Error updating notes' });
    }
});

// Reset progress for a course
router.delete('/course/:courseId', ensureAuthenticated, async (req, res) => {
    try {
        const { courseId } = req.params;

        const chapters = await Chapter.findAll({
            where: { courseId },
            include: [{ model: Lab, as: 'labs' }]
        });

        const chapterIds = chapters.map(c => c.id);
        const labIds = chapters.flatMap(c => c.labs.map(l => l.id));

        // Delete all progress for this course
        await Progress.destroy({
            where: {
                userId: req.user.id,
                [require('sequelize').Op.or]: [
                    { chapterId: chapterIds },
                    { labId: labIds }
                ]
            }
        });

        res.json({ success: true, message: 'Progress reset' });
    } catch (error) {
        console.error('Error resetting progress:', error);
        res.status(500).json({ error: 'Error resetting progress' });
    }
});

// Get stats for dashboard
router.get('/stats', ensureAuthenticated, async (req, res) => {
    try {
        const completedChapters = await Progress.count({
            where: {
                userId: req.user.id,
                status: 'completed',
                chapterId: { [require('sequelize').Op.ne]: null }
            }
        });

        const completedLabs = await Progress.count({
            where: {
                userId: req.user.id,
                status: 'completed',
                labId: { [require('sequelize').Op.ne]: null }
            }
        });

        const inProgress = await Progress.count({
            where: {
                userId: req.user.id,
                status: 'in_progress'
            }
        });

        const totalTimeSpent = await Progress.sum('timeSpentMinutes', {
            where: { userId: req.user.id }
        }) || 0;

        res.json({
            success: true,
            stats: {
                completedChapters,
                completedLabs,
                inProgress,
                totalTimeSpent
            }
        });
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({ error: 'Error getting stats' });
    }
});

module.exports = router;
