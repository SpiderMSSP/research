'use strict';

module.exports = (sequelize, DataTypes) => {
    const Lab = sequelize.define('Lab', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        chapterId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'chapters',
                key: 'id'
            }
        },
        title: {
            type: DataTypes.STRING(255),
            allowNull: false
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: true
        },
        difficulty: {
            type: DataTypes.ENUM('easy', 'medium', 'hard', 'expert'),
            defaultValue: 'medium'
        },
        walkthrough: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: 'Step-by-step walkthrough in Markdown'
        },
        solution: {
            type: DataTypes.TEXT,
            allowNull: true,
            comment: 'Full solution (hidden by default)'
        },
        hints: {
            type: DataTypes.ARRAY(DataTypes.TEXT),
            defaultValue: [],
            comment: 'Progressive hints revealed one at a time'
        },
        filesPath: {
            type: DataTypes.STRING(500),
            allowNull: true,
            comment: 'Path to lab files directory'
        },
        orderIndex: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0
        },
        estimatedMinutes: {
            type: DataTypes.INTEGER,
            allowNull: true
        },
        objectives: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: []
        },
        prerequisites: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: [],
            comment: 'Skills or knowledge required before attempting'
        },
        tools: {
            type: DataTypes.ARRAY(DataTypes.STRING),
            defaultValue: [],
            comment: 'Tools needed for this lab (gcc, gdb, etc.)'
        },
        flagFormat: {
            type: DataTypes.STRING(255),
            allowNull: true,
            comment: 'Format hint for CTF-style flags if applicable'
        },
        flag: {
            type: DataTypes.STRING(255),
            allowNull: true,
            comment: 'Actual flag for verification (stored hashed)'
        }
    }, {
        tableName: 'labs',
        underscored: true
    });

    // Check if a flag submission is correct
    Lab.prototype.checkFlag = function(submission) {
        if (!this.flag) return null; // No flag to check
        return submission.trim() === this.flag;
    };

    return Lab;
};
