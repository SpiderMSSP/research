'use strict';

const bcrypt = require('bcryptjs');

module.exports = (sequelize, DataTypes) => {
    const User = sequelize.define('User', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        username: {
            type: DataTypes.STRING(50),
            allowNull: false,
            unique: true,
            validate: {
                len: [3, 50],
                isAlphanumeric: true
            }
        },
        email: {
            type: DataTypes.STRING(255),
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true
            }
        },
        password: {
            type: DataTypes.STRING(255),
            allowNull: false
        },
        role: {
            type: DataTypes.ENUM('student', 'instructor', 'admin'),
            defaultValue: 'student'
        },
        avatarUrl: {
            type: DataTypes.STRING(500),
            allowNull: true
        },
        bio: {
            type: DataTypes.TEXT,
            allowNull: true
        }
    }, {
        tableName: 'users',
        underscored: true,
        hooks: {
            beforeCreate: async (user) => {
                if (user.password) {
                    const salt = await bcrypt.genSalt(10);
                    user.password = await bcrypt.hash(user.password, salt);
                }
            },
            beforeUpdate: async (user) => {
                if (user.changed('password')) {
                    const salt = await bcrypt.genSalt(10);
                    user.password = await bcrypt.hash(user.password, salt);
                }
            }
        }
    });

    // Instance method to check password
    User.prototype.validPassword = async function(password) {
        return await bcrypt.compare(password, this.password);
    };

    // Instance method to check if user can edit courses
    User.prototype.canEditCourses = function() {
        return ['instructor', 'admin'].includes(this.role);
    };

    // Instance method to check if user is admin
    User.prototype.isAdmin = function() {
        return this.role === 'admin';
    };

    return User;
};
