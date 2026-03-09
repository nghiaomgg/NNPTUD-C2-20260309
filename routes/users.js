const express = require("express");
const router = express.Router();
const { postUserValidator, validateResult } = require('../utils/validatorHandler');
const userController = require('../controllers/users');
const { checkLogin, checkRole } = require('../utils/authHandler.js');
const userModel = require("../schemas/users");

/**
 * GET /api/v1/users
 * Lấy danh sách tất cả users (ADMIN, MODERATOR)
 */
router.get("/", checkLogin, checkRole("ADMIN", "MODERATOR"),
  async function (req, res, next) {
    try {
      const users = await userModel
        .find({ isDeleted: false })
        .populate({
          path: 'role',
          select: 'name'
        })
        .select('-password'); // Không trả về password
      res.json({
        success: true,
        data: users
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Lỗi lấy danh sách người dùng.'
      });
    }
  }
);

/**
 * GET /api/v1/users/:id
 * Lấy thông tin user theo ID (ADMIN, MODERATOR)
 */
router.get("/:id", checkLogin, checkRole("ADMIN", "MODERATOR"),
  async function (req, res, next) {
    try {
      const result = await userModel
        .findOne({ _id: req.params.id, isDeleted: false })
        .populate({
          path: 'role',
          select: 'name'
        })
        .select('-password');

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Không tìm thấy người dùng.'
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
 * POST /api/v1/users
 * Tạo user mới (chỉ ADMIN)
 */
router.post("/", checkLogin, checkRole("ADMIN"),
  postUserValidator, validateResult,
  async function (req, res, next) {
    try {
      const newUser = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        req.body.role
      );

      const saved = await userModel
        .findById(newUser._id)
        .populate({
          path: 'role',
          select: 'name'
        })
        .select('-password');

      res.status(201).json({
        success: true,
        message: 'Tạo người dùng thành công.',
        data: saved
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({
          success: false,
          message: 'Username hoặc email đã tồn tại.'
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
 * PUT /api/v1/users/:id
 * Cập nhật thông tin user (chỉ ADMIN)
 * Không cho phép cập nhật password qua route này — dùng /auth/change-password
 */
router.put("/:id", checkLogin, checkRole("ADMIN"),
  async function (req, res, next) {
    try {
      const id = req.params.id;

      // Không cho cập nhật các field nhạy cảm qua route này
      const { password, isDeleted, ...updateData } = req.body;

      const updatedItem = await userModel.findOne({
        _id: id,
        isDeleted: false
      });

      if (!updatedItem) {
        return res.status(404).json({
          success: false,
          message: 'Không tìm thấy người dùng.'
        });
      }

      for (const key of Object.keys(updateData)) {
        updatedItem[key] = updateData[key];
      }
      await updatedItem.save();

      const populated = await userModel
        .findById(updatedItem._id)
        .populate({
          path: 'role',
          select: 'name'
        })
        .select('-password');

      res.json({
        success: true,
        message: 'Cập nhật người dùng thành công.',
        data: populated
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
 * DELETE /api/v1/users/:id
 * Xóa mềm user (chỉ ADMIN)
 */
router.delete("/:id", checkLogin, checkRole("ADMIN"),
  async function (req, res, next) {
    try {
      const id = req.params.id;

      // Không cho ADMIN xóa chính mình
      if (id === req.userId) {
        return res.status(400).json({
          success: false,
          message: 'Không thể xóa chính mình.'
        });
      }

      const updatedItem = await userModel.findByIdAndUpdate(
        id,
        { isDeleted: true },
        { new: true }
      );

      if (!updatedItem) {
        return res.status(404).json({
          success: false,
          message: 'Không tìm thấy người dùng.'
        });
      }

      res.json({
        success: true,
        message: 'Xóa người dùng thành công.',
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