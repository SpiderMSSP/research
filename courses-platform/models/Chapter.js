'use strict';

const slugify = require('slugify');

module.exports = (sequelize, DataTypes) => {
    const Chapter = sequelize.define('Chapter', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        courseId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'courses',
                key: 'id'
            }
        },
        title: {
            type: DataTypes.STRING(255),
            allowNull: false
        },
        slug: {
            type: DataTypes.STRING(255),
            allowNull: false
        },
        content: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: 'Markdown content for the chapter'
        },
        orderIndex: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        storyContext: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: 'Narrative context connecting this chapter to the story'
        },
        previouslySummary: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: '"Previously on..." summary from prior chapters'
        },
        learningObjectives: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: []
        },
        estimatedMinutes: {
            type: DataTypes.INTEGER,
            allowNull: true
        },
        videoUrl: {
            type: DataTypes.STRING(500),
            allowNull: true
        },
        resourceLinks: {
            type: DataTypes.JSONB,
            defaultValue: [],
            comment: 'Array of {title, url, type} objects for additional resources'
        }
    }, {
        tableName: 'chapters',
        underscored: true,
        indexes: [
            {
                unique: true,
                fields: ['course_id', 'slug']
            }
        ],
        hooks: {
            beforeCreate: (chapter) => {
                if (chapter.title && !chapter.slug) {
                    chapter.slug = slugify(chapter.title, { lower: true, strict: true });
                }
            },
            beforeUpdate: (chapter) => {
                if (chapter.changed('title')) {
                    chapter.slug = slugify(chapter.title, { lower: true, strict: true });
                }
            }
        }
    });

    // Get the next chapter in the course
    Chapter.prototype.getNextChapter = async function() {
        return await Chapter.findOne({
            where: {
                courseId: this.courseId,
                orderIndex: { [sequelize.Sequelize.Op.gt]: this.orderIndex }
            },
            order: [['orderIndex', 'ASC']]
        });
    };

    // Get the previous chapter in the course
    Chapter.prototype.getPreviousChapter = async function() {
        return await Chapter.findOne({
            where: {
                courseId: this.courseId,
                orderIndex: { [sequelize.Sequelize.Op.lt]: this.orderIndex }
            },
            order: [['orderIndex', 'DESC']]
        });
    };

    return Chapter;
};
