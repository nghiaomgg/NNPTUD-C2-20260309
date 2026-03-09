const express = require("express");
const router = express.Router();
const roleModel = require("../schemas/roles");
const { checkLogin, checkRole } = require('../utils/authHandler.js');

/**
 * GET /api/v1/roles
 * Lấy danh sách tất cả roles (ADMIN, MODERATOR)
 */
router.get("/", checkLogin, checkRole("ADMIN", "MODERATOR"),
    async function (req, res, next) {
        try {
            const roles = await roleModel.find({ isDeleted: false });
            res.json({
                success: true,
                data: roles
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: 'Lỗi lấy danh sách role.'
            });
        }
    }
);

/**
 * GET /api/v1/roles/:id
 * Lấy thông tin role theo ID (ADMIN, MODERATOR)
 */
router.get("/:id", checkLogin, checkRole("ADMIN", "MODERATOR"),
    async function (req, res, next) {
        try {
            const result = await roleModel.findOne({
                _id: req.params.id,
                isDeleted: false
            });

            if (!result) {
                return res.status(404).json({
                    success: false,
                    message: 'Không tìm thấy role.'
                });
            }
            res.json({
                success: true,
                data: result
            });
        } catch (error) {
            res.status(404).json({
                success: false,
                message: 'ID không hợp lệ.'
            });
        }
    }
);

/**
 * POST /api/v1/roles
 * Tạo role mới (chỉ ADMIN)
 */
router.post("/", checkLogin, checkRole("ADMIN"),
    async function (req, res, next) {
        try {
            const newItem = new roleModel({
                name: req.body.name,
                description: req.body.description
            });
            await newItem.save();
            res.status(201).json({
                success: true,
                message: 'Tạo role thành công.',
                data: newItem
            });
        } catch (err) {
            if (err.code === 11000) {
                return res.status(409).json({
                    success: false,
                    message: 'Tên role đã tồn tại.'
                });
            }
            res.status(400).json({
                success: false,
                message: err.message
            });
        }
    }
);

/**
 * PUT /api/v1/roles/:id
 * Cập nhật role (chỉ ADMIN)
 */
router.put("/:id", checkLogin, checkRole("ADMIN"),
    async function (req, res, next) {
        try {
            const updatedItem = await roleModel.findByIdAndUpdate(
                req.params.id,
                req.body,
                { new: true, runValidators: true }
            );

            if (!updatedItem) {
                return res.status(404).json({
                    success: false,
                    message: 'Không tìm thấy role.'
                });
            }
            res.json({
                success: true,
                message: 'Cập nhật role thành công.',
                data: updatedItem
            });
        } catch (err) {
            res.status(400).json({
                success: false,
                message: err.message
            });
        }
    }
);

/**
 * DELETE /api/v1/roles/:id
 * Xóa mềm role (chỉ ADMIN)
 */
router.delete("/:id", checkLogin, checkRole("ADMIN"),
    async function (req, res, next) {
        try {
            const updatedItem = await roleModel.findByIdAndUpdate(
                req.params.id,
                { isDeleted: true },
                { new: true }
            );

            if (!updatedItem) {
                return res.status(404).json({
                    success: false,
                    message: 'Không tìm thấy role.'
                });
            }
            res.json({
                success: true,
                message: 'Xóa role thành công.',
                data: { id: updatedItem._id }
            });
        } catch (err) {
            res.status(400).json({
                success: false,
                message: err.message
            });
        }
    }
);

module.exports = router;