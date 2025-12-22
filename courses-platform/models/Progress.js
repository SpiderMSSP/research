'use strict';

module.exports = (sequelize, DataTypes) => {
    const Progress = sequelize.define('Progress', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'users',
                key: 'id'
            }
        },
        chapterId: {
            type: DataTypes.INTEGER,
            allowNull: true,
            references: {
                model: 'chapters',
                key: 'id'
            }
        },
        labId: {
            type: DataTypes.INTEGER,
            allowNull: true,
            references: {
                model: 'labs',
                key: 'id'
            }
        },
        status: {
            type: DataTypes.ENUM('not_started', 'in_progress', 'completed'),
            defaultValue: 'not_started'
        },
        completedAt: {
            type: DataTypes.DATE,
            allowNull: true
        },
        notes: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: "User's personal notes about this section"
        },
        hintsUsed: {
            type: DataTypes.INTEGER,
            defaultValue: 0,
            comment: 'Number of hints the user has revealed'
        },
        timeSpentMinutes: {
            type: DataTypes.INTEGER,
            defaultValue: 0
        },
        lastAccessedAt: {
            type: DataTypes.DATE,
            defaultValue: DataTypes.NOW
        }
    }, {
        tableName: 'progress',
        underscored: true,
        indexes: [
            {
                unique: true,
                fields: ['user_id', 'chapter_id'],
                where: { chapter_id: { [sequelize.Sequelize.Op.ne]: null } }
            },
            {
                unique: true,
                fields: ['user_id', 'lab_id'],
                where: { lab_id: { [sequelize.Sequelize.Op.ne]: null } }
            }
        ]
    });

    // Mark as completed
    Progress.prototype.markComplete = async function() {
        this.status = 'completed';
        this.completedAt = new Date();
        await this.save();
    };

    // Mark as in progress
    Progress.prototype.markInProgress = async function() {
        if (this.status === 'not_started') {
            this.status = 'in_progress';
            await this.save();
        }
    };

    // Update time spent
    Progress.prototype.addTime = async function(minutes) {
        this.timeSpentMinutes += minutes;
        this.lastAccessedAt = new Date();
        await this.save();
    };

    // Static method to get or create progress
    Progress.getOrCreate = async function(userId, { chapterId = null, labId = null }) {
        const where = { userId };
        if (chapterId) where.chapterId = chapterId;
        if (labId) where.labId = labId;

        let [progress, created] = await this.findOrCreate({
            where,
            defaults: { status: 'not_started' }
        });

        return progress;
    };

    // Static method to get course progress percentage
    Progress.getCourseProgress = async function(userId, courseId) {
        const { Chapter, Lab } = sequelize.models;

        // Get all chapters in course
        const chapters = await Chapter.findAll({
            where: { courseId },
            include: ['labs']
        });

        let totalItems = 0;
        let completedItems = 0;

        for (const chapter of chapters) {
            totalItems++; // Count chapter
            totalItems += chapter.labs.length; // Count labs

            // Check chapter progress
            const chapterProgress = await this.findOne({
                where: { userId, chapterId: chapter.id }
            });
            if (chapterProgress?.status === 'completed') completedItems++;

            // Check lab progress
            for (const lab of chapter.labs) {
                const labProgress = await this.findOne({
                    where: { userId, labId: lab.id }
                });
                if (labProgress?.status === 'completed') completedItems++;
            }
        }

        return totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;
    };

    return Progress;
};
