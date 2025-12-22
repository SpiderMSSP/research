'use strict';

require('dotenv').config();
const { Sequelize } = require('sequelize');

const env = process.env.NODE_ENV || 'development';
const config = require('../config/database')[env];

const sequelize = new Sequelize(
    config.database,
    config.username,
    config.password,
    {
        host: config.host,
        port: config.port,
        dialect: config.dialect,
        logging: config.logging,
        pool: config.pool
    }
);

const db = {};

// Import models
db.User = require('./User')(sequelize, Sequelize.DataTypes);
db.Course = require('./Course')(sequelize, Sequelize.DataTypes);
db.Chapter = require('./Chapter')(sequelize, Sequelize.DataTypes);
db.Lab = require('./Lab')(sequelize, Sequelize.DataTypes);
db.Progress = require('./Progress')(sequelize, Sequelize.DataTypes);

// Define associations
// Course -> Chapters (one-to-many)
db.Course.hasMany(db.Chapter, {
    foreignKey: 'courseId',
    as: 'chapters',
    onDelete: 'CASCADE'
});
db.Chapter.belongsTo(db.Course, {
    foreignKey: 'courseId',
    as: 'course'
});

// Chapter -> Labs (one-to-many)
db.Chapter.hasMany(db.Lab, {
    foreignKey: 'chapterId',
    as: 'labs',
    onDelete: 'CASCADE'
});
db.Lab.belongsTo(db.Chapter, {
    foreignKey: 'chapterId',
    as: 'chapter'
});

// User -> Courses (creator relationship)
db.User.hasMany(db.Course, {
    foreignKey: 'createdBy',
    as: 'createdCourses'
});
db.Course.belongsTo(db.User, {
    foreignKey: 'createdBy',
    as: 'creator'
});

// User -> Progress (one-to-many)
db.User.hasMany(db.Progress, {
    foreignKey: 'userId',
    as: 'progress',
    onDelete: 'CASCADE'
});
db.Progress.belongsTo(db.User, {
    foreignKey: 'userId',
    as: 'user'
});

// Chapter -> Progress
db.Chapter.hasMany(db.Progress, {
    foreignKey: 'chapterId',
    as: 'progress'
});
db.Progress.belongsTo(db.Chapter, {
    foreignKey: 'chapterId',
    as: 'chapter'
});

// Lab -> Progress
db.Lab.hasMany(db.Progress, {
    foreignKey: 'labId',
    as: 'progress'
});
db.Progress.belongsTo(db.Lab, {
    foreignKey: 'labId',
    as: 'lab'
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
