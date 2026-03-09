const jwt = require('jsonwebtoken');
const userController = require('../controllers/users');

const JWT_SECRET = 'secret';

module.exports = {
    /**
     * Middleware kiểm tra đăng nhập.
     * Hỗ trợ token từ cookie hoặc Authorization header (Bearer token).
     * Gắn req.userId nếu token hợp lệ.
     */
    checkLogin: async function (req, res, next) {
        try {
            let token;

            // Ưu tiên lấy token từ cookie
            if (req.cookies && req.cookies.token) {
                token = req.cookies.token;
            } else {
                // Fallback lấy từ Authorization header
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return res.status(401).json({
                        success: false,
                        message: 'Bạn chưa đăng nhập. Vui lòng cung cấp token.'
                    });
                }
                token = authHeader.split(' ')[1];
            }

            if (!token) {
                return res.status(401).json({
                    success: false,
                    message: 'Token không tồn tại.'
                });
            }

            // Verify token — jwt.verify tự throw nếu hết hạn hoặc sai signature
            const decoded = jwt.verify(token, JWT_SECRET);
            req.userId = decoded.id;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({
                    success: false,
                    message: 'Token đã hết hạn. Vui lòng đăng nhập lại.'
                });
            }
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({
                    success: false,
                    message: 'Token không hợp lệ.'
                });
            }
            return res.status(500).json({
                success: false,
                message: 'Lỗi xác thực.'
            });
        }
    },

    /**
     * Middleware kiểm tra quyền (role-based).
     * Nhận danh sách role được phép, so sánh với role hiện tại của user.
     * 
     * @param  {...string} allowedRoles - Danh sách role name được phép truy cập
     * @returns {Function} Express middleware
     * 
     * @example
     * // Chỉ ADMIN được truy cập
     * router.delete('/:id', checkLogin, checkRole('ADMIN'), handler);
     * 
     * // ADMIN hoặc MODERATOR được truy cập
     * router.get('/', checkLogin, checkRole('ADMIN', 'MODERATOR'), handler);
     */
    checkRole: function (...allowedRoles) {
        return async function (req, res, next) {
            try {
                const userId = req.userId;
                if (!userId) {
                    return res.status(401).json({
                        success: false,
                        message: 'Bạn chưa đăng nhập.'
                    });
                }

                const user = await userController.FindUserById(userId);
                if (!user) {
                    return res.status(404).json({
                        success: false,
                        message: 'Người dùng không tồn tại.'
                    });
                }

                if (!user.role || !user.role.name) {
                    return res.status(403).json({
                        success: false,
                        message: 'Người dùng chưa được gán role.'
                    });
                }

                const currentRole = user.role.name;
                if (!allowedRoles.includes(currentRole)) {
                    return res.status(403).json({
                        success: false,
                        message: `Bạn không có quyền truy cập. Yêu cầu role: [${allowedRoles.join(', ')}]`
                    });
                }

                // Gắn thông tin role vào request để các handler sau dùng
                req.userRole = currentRole;
                next();
            } catch (error) {
                return res.status(500).json({
                    success: false,
                    message: 'Lỗi kiểm tra quyền truy cập.'
                });
            }
        };
    }
};