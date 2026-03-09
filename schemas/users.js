const mongoose = require("mongoose");
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, "Username is required"],
            unique: true,
            trim: true
        },

        password: {
            type: String,
            required: [true, "Password is required"]
        },

        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            lowercase: true,
            trim: true,
            match: [/^\S+@\S+\.\S+$/, "Invalid email format"]
        },

        fullName: {
            type: String,
            default: ""
        },

        avatarUrl: {
            type: String,
            default: "https://i.sstatic.net/l60Hf.png"
        },

        status: {
            type: Boolean,
            default: false
        },

        role: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "role",
            required: true
        },

        loginCount: {
            type: Number,
            default: 0,
            min: [0, "Login count cannot be negative"]
        },

        isDeleted: {
            type: Boolean,
            default: false
        }
    },
    {
        timestamps: true
    }
);

userSchema.index({
    username: 1,
    email: 1
});

/**
 * Pre-save hook: Chỉ hash password khi password bị thay đổi (isModified).
 * Tránh hash lại password đã hash khi update các field khác.
 */
userSchema.pre('save', async function (next) {
    // Chỉ hash khi password thực sự thay đổi
    if (!this.isModified('password')) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

/**
 * Instance method: So sánh password plaintext với password đã hash.
 * @param {string} candidatePassword - Password plaintext cần kiểm tra
 * @returns {Promise<boolean>}
 */
userSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("user", userSchema);