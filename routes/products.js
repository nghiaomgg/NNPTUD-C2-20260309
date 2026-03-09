const express = require('express');
const slugify = require('slugify');
const router = express.Router();
const modelProduct = require('../schemas/products');
const { checkLogin, checkRole } = require('../utils/authHandler.js');

/**
 * GET /api/v1/products
 * Lấy danh sách sản phẩm — PUBLIC (không cần đăng nhập)
 * Hỗ trợ filter: title, minPrice, maxPrice, limit, page
 */
router.get('/', async function (req, res, next) {
  try {
    const { title = '', maxPrice, minPrice = 0, limit = 5, page = 1 } = req.query;

    const filter = {
      isDeleted: false,
      price: {
        $gte: Number(minPrice),
        $lte: maxPrice ? Number(maxPrice) : Number.MAX_SAFE_INTEGER
      }
    };

    // Filter theo title (case-insensitive)
    if (title) {
      filter.title = { $regex: title, $options: 'i' };
    }

    const pageNum = Math.max(1, Number(page));
    const limitNum = Math.max(1, Number(limit));
    const skip = limitNum * (pageNum - 1);

    const [data, total] = await Promise.all([
      modelProduct.find(filter).skip(skip).limit(limitNum),
      modelProduct.countDocuments(filter)
    ]);

    res.json({
      success: true,
      data: data,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: total,
        totalPages: Math.ceil(total / limitNum)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Lỗi lấy danh sách sản phẩm.'
    });
  }
});

/**
 * GET /api/v1/products/:id
 * Lấy chi tiết sản phẩm — PUBLIC (không cần đăng nhập)
 */
router.get('/:id', async function (req, res, next) {
  try {
    const result = await modelProduct.findOne({
      _id: req.params.id,
      isDeleted: false
    });

    if (!result) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy sản phẩm.'
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
});

/**
 * POST /api/v1/products
 * Tạo sản phẩm mới (ADMIN, MODERATOR — yêu cầu đăng nhập)
 */
router.post('/', checkLogin, checkRole('ADMIN', 'MODERATOR'),
  async function (req, res, next) {
    try {
      const { title, price, description, category, images } = req.body;

      if (!title || !category) {
        return res.status(400).json({
          success: false,
          message: 'Vui lòng cung cấp title và category.'
        });
      }

      const newProduct = new modelProduct({
        title,
        slug: slugify(title, {
          replacement: '-',
          remove: undefined,
          locale: 'vi',
          trim: true,
          lower: true
        }),
        price,
        description,
        category,
        images
      });
      await newProduct.save();

      res.status(201).json({
        success: true,
        message: 'Tạo sản phẩm thành công.',
        data: newProduct
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({
          success: false,
          message: 'Slug sản phẩm đã tồn tại. Vui lòng đổi tên.'
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
 * PUT /api/v1/products/:id
 * Cập nhật sản phẩm (ADMIN, MODERATOR — yêu cầu đăng nhập)
 */
router.put('/:id', checkLogin, checkRole('ADMIN', 'MODERATOR'),
  async function (req, res, next) {
    try {
      const updateData = { ...req.body };

      // Nếu cập nhật title → tự động tạo slug mới
      if (updateData.title) {
        updateData.slug = slugify(updateData.title, {
          replacement: '-',
          remove: undefined,
          locale: 'vi',
          trim: true,
          lower: true
        });
      }

      // Không cho phép thay đổi isDeleted qua PUT
      delete updateData.isDeleted;

      const result = await modelProduct.findOneAndUpdate(
        { _id: req.params.id, isDeleted: false },
        updateData,
        { new: true, runValidators: true }
      );

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Không tìm thấy sản phẩm.'
        });
      }

      res.json({
        success: true,
        message: 'Cập nhật sản phẩm thành công.',
        data: result
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
 * DELETE /api/v1/products/:id
 * Xóa mềm sản phẩm (chỉ ADMIN — yêu cầu đăng nhập)
 */
router.delete('/:id', checkLogin, checkRole('ADMIN'),
  async function (req, res, next) {
    try {
      const result = await modelProduct.findOneAndUpdate(
        { _id: req.params.id, isDeleted: false },
        { isDeleted: true },
        { new: true }
      );

      if (!result) {
        return res.status(404).json({
          success: false,
          message: 'Không tìm thấy sản phẩm.'
        });
      }

      res.json({
        success: true,
        message: 'Xóa sản phẩm thành công.',
        data: { id: result._id }
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
