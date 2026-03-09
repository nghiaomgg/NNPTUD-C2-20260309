const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const userController = require('../controllers/users');
const { checkLogin } = require('../utils/authHandler.js');

const JWT_SECRET = 'secret';
const TOKEN_EXPIRY = '1h';
const COOKIE_MAX_AGE = 60 * 60 * 1000; // 1 giờ

/**
 * POST /api/v1/auth/register
 * Đăng ký tài khoản mới (role mặc định: user thường)
 */
router.post('/register', async function (req, res, next) {
    try {
        const { username, password, email } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng cung cấp đầy đủ username, password, email.'
            });
        }

        const newUser = await userController.CreateAnUser(
            username, password, email,
            "69a5462f086d74c9e772b804" // Role mặc định
        );

        res.status(201).json({
            success: true,
            message: 'Đăng ký thành công.',
            data: {
                id: newUser._id,
                username: newUser.username,
                email: newUser.email
            }
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: 'Username hoặc email đã tồn tại.'
            });
        }
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

/**
 * POST /api/v1/auth/login
 * Đăng nhập — trả về JWT token qua cookie và response body
 */
router.post('/login', async function (req, res, next) {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng cung cấp username và password.'
            });
        }

        const user = await userController.QueryByUserNameAndPassword(username, password);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Sai thông tin đăng nhập.'
            });
        }

        const token = jwt.sign(
            { id: user._id },
            JWT_SECRET,
            { expiresIn: TOKEN_EXPIRY }
        );

        res.cookie('token', token, {
            maxAge: COOKIE_MAX_AGE,
            httpOnly: true
        });

        res.json({
            success: true,
            message: 'Đăng nhập thành công.',
            token: token
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Lỗi đăng nhập.'
        });
    }
});

/**
 * GET /api/v1/auth/me
 * Lấy thông tin user hiện tại (yêu cầu đăng nhập)
 */
router.get('/me', checkLogin, async function (req, res, next) {
    try {
        const user = await userController.FindUserById(req.userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Người dùng không tồn tại.'
            });
        }
        res.json({
            success: true,
            data: user
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Lỗi lấy thông tin người dùng.'
        });
    }
});

/**
 * PUT /api/v1/auth/change-password
 * Đổi mật khẩu (yêu cầu đăng nhập)
 * Body: { oldPassword, newPassword }
 */
router.put('/change-password', checkLogin, async function (req, res, next) {
    try {
        const { oldPassword, newPassword } = req.body;

        // Validate input
        if (!oldPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng cung cấp oldPassword và newPassword.'
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Mật khẩu mới phải có ít nhất 8 ký tự.'
            });
        }

        const result = await userController.ChangePassword(
            req.userId, oldPassword, newPassword
        );

        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: result.message
            });
        }

        // Xóa cookie cũ — buộc đăng nhập lại với mật khẩu mới
        res.cookie('token', null, {
            maxAge: 0,
            httpOnly: true
        });

        res.json({
            success: true,
            message: result.message
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Lỗi đổi mật khẩu.'
        });
    }
});

/**
 * POST /api/v1/auth/logout
 * Đăng xuất — xóa token cookie
 */
router.post('/logout', checkLogin, function (req, res, next) {
    res.cookie('token', null, {
        maxAge: 0,
        httpOnly: true
    });
    res.json({
        success: true,
        message: 'Đăng xuất thành công.'
    });
});

module.exports = router;
