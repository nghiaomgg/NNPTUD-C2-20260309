const userModel = require('../schemas/users');

module.exports = {
    /**
     * Tạo user mới.
     */
    CreateAnUser: async function (username, password, email, role,
        avatarUrl, fullName, status, loginCount
    ) {
        const newUser = new userModel({
            username,
            password,
            email,
            role,
            avatarUrl,
            fullName,
            status,
            loginCount
        });
        await newUser.save();
        return newUser;
    },

    /**
     * Xác thực đăng nhập bằng username + password.
     * Sử dụng bcrypt.compare để so sánh password an toàn.
     * @returns {Object|false} - Trả về user nếu hợp lệ, false nếu sai thông tin
     */
    QueryByUserNameAndPassword: async function (username, password) {
        const user = await userModel.findOne({
            username: username,
            isDeleted: false
        });
        if (!user) {
            return false;
        }

        // So sánh password plaintext với hash trong DB
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return false;
        }

        return user;
    },

    /**
     * Tìm user theo ID (chỉ user chưa bị xóa), populate role.
     */
    FindUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted: false
        }).populate('role');
    },

    /**
     * Đổi mật khẩu user.
     * Kiểm tra oldPassword trước khi cập nhật newPassword.
     * 
     * @param {string} userId - ID của user
     * @param {string} oldPassword - Mật khẩu cũ (plaintext)
     * @param {string} newPassword - Mật khẩu mới (plaintext)
     * @returns {Object} - { success: boolean, message: string }
     */
    ChangePassword: async function (userId, oldPassword, newPassword) {
        const user = await userModel.findOne({
            _id: userId,
            isDeleted: false
        });

        if (!user) {
            return {
                success: false,
                message: 'Người dùng không tồn tại.'
            };
        }

        // Verify mật khẩu cũ
        const isMatch = await user.comparePassword(oldPassword);
        if (!isMatch) {
            return {
                success: false,
                message: 'Mật khẩu cũ không chính xác.'
            };
        }

        // Kiểm tra mật khẩu mới không trùng mật khẩu cũ
        const isSame = await user.comparePassword(newPassword);
        if (isSame) {
            return {
                success: false,
                message: 'Mật khẩu mới không được trùng với mật khẩu cũ.'
            };
        }

        // Cập nhật password mới — pre('save') hook sẽ tự hash
        user.password = newPassword;
        await user.save();

        return {
            success: true,
            message: 'Đổi mật khẩu thành công.'
        };
    }
};