'use strict';

const slugify = require('slugify');

module.exports = (sequelize, DataTypes) => {
    const Course = sequelize.define('Course', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        title: {
            type: DataTypes.STRING(255),
            allowNull: false,
            validate: {
                len: [3, 255]
            }
        },
        slug: {
            type: DataTypes.STRING(255),
            unique: true
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: true
        },
        shortDescription: {
            type: DataTypes.STRING(500),
            allowNull: true
        },
        coverImage: {
            type: DataTypes.STRING(500),
            allowNull: true
        },
        difficulty: {
            type: DataTypes.ENUM('beginner', 'intermediate', 'advanced', 'expert'),
            defaultValue: 'intermediate'
        },
        estimatedHours: {
            type: DataTypes.INTEGER,
            allowNull: true
        },
        isPublished: {
            type: DataTypes.BOOLEAN,
            defaultValue: false
        },
        orderIndex: {
            type: DataTypes.INTEGER,
            defaultValue: 0
        },
        tags: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: []
        },
        prerequisites: {
            type: DataTypes.TEXT,
            allowNull: true
        },
        objectives: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: []
        },
        createdBy: {
            type: DataTypes.INTEGER,
            allowNull: true,
            references: {
                model: 'users',
                key: 'id'
            }
        }
    }, {
        tableName: 'courses',
        underscored: true,
        hooks: {
            beforeCreate: (course) => {
                if (course.title && !course.slug) {
                    course.slug = slugify(course.title, { lower: true, strict: true });
                }
            },
            beforeUpdate: (course) => {
                if (course.changed('title')) {
                    course.slug = slugify(course.title, { lower: true, strict: true });
                }
            }
        }
    });

    // Class method to get course with full details
    Course.getFullCourse = async function(slug) {
        return await this.findOne({
            where: { slug },
            include: [{
                association: 'chapters',
                include: ['labs'],
                order: [['orderIndex', 'ASC']]
            }, {
                association: 'creator',
                attributes: ['id', 'username', 'avatarUrl']
            }],
            order: [
                [{ model: sequelize.models.Chapter, as: 'chapters' }, 'orderIndex', 'ASC']
            ]
        });
    };

    return Course;
};
