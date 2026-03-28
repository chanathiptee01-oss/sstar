require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    const name = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, name);
  },
});
const upload = multer({ storage });

// MongoDB Connection
if (!MONGO_URI) {
  console.error('❌ MONGO_URI is not set. Please configure it in the environment.');
  process.exit(1);
}

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, default: '' },
  password: { type: String, required: true }, // Should be hashed in prod
  role: { type: String, default: 'user', enum: ['user', 'admin'] }
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  price: { type: Number, required: true, min: 0 },
  description: { type: String, default: '' },
  category: { type: String, default: '' },
  image: { type: String, default: '' }
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  orderCode: { type: String, default: '' },
  customerName: { type: String, required: true },
  companyName: { type: String, default: '' },
  houseNumber: { type: String, default: '' },
  addressDetail: { type: String, default: '' },
  shippingAddress: { type: String, default: '' },
  productDetails: { type: mongoose.Schema.Types.Mixed, required: true },
  quantity: { type: Number, default: 1 },
  totalAmount: { type: Number, required: true },
  status: { type: Number, default: 0 }, // 0-6
  statusHistory: [
    {
      status: { type: Number, required: true },
      changedAt: { type: Date, default: Date.now },
      changedBy: { type: String, default: '' },
    },
  ],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// --- Endpoints ---

// Check server status
app.get('/', (req, res) => {
  res.send('SStar Backend Server API is running with MongoDB!');
});

// GET all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({
      title: { $exists: true, $ne: '' },
      price: { $ne: null },
    });

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read products', details: err.message });
  }
});

// POST register user
app.post('/api/auth/register', async (req, res) => {
  const { username, password, name } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const role = 'user';

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ username, name: name || '', password: hashedPassword, role });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully', role });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// POST login user
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (user) {
      // Check hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (isMatch) {
        // Encode role in fake token for easy client side decoding (or use `/auth/me`)
        const token = `mock_token_${user._id}_${Date.now()}`;
        res.json({ token, message: 'Login successful', role: user.role, userId: user._id });
      } else {
        res.status(401).json({ error: 'Invalid username or password' });
      }
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

const getUserIdFromToken = (authHeader) => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.split(' ')[1];
  if (!token || !token.startsWith('mock_token_')) return null;
  const parts = token.split('_');
  return parts.length >= 3 ? parts[2] : null;
};

const requireAuth = async (req, res, next) => {
  try {
    const userId = getUserIdFromToken(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    req.userId = userId;
    return next();
  } catch (err) {
    return res.status(500).json({ error: 'Authorization failed' });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const userId = getUserIdFromToken(req.headers.authorization);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    const user = await User.findById(userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  } catch (err) {
    return res.status(500).json({ error: 'Authorization failed' });
  }
};

// GET /auth/me - Get current user profile based on user_id 
app.get('/api/auth/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id, '-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// PATCH /auth/user/:id - Update user profile (self or admin)
app.patch('/api/auth/user/:id', requireAuth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.userId !== req.params.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const updates = {};
    if (typeof req.body.name === 'string') {
      updates.name = req.body.name.trim();
    }
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { returnDocument: 'after', select: '-password' }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// POST add a new product (Admin)
app.post('/api/products', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const priceRaw = typeof req.body.price === 'string' ? req.body.price.trim() : req.body.price;
    const price = Number.parseFloat(priceRaw);
    if (!title || Number.isNaN(price)) {
      return res.status(400).json({ error: 'Title and price are required' });
    }
    const imageUrl = req.file
      ? `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`
      : (typeof req.body.imageUrl === 'string' ? req.body.imageUrl : '');
    const newProduct = new Product({
      title,
      price,
      description: typeof req.body.description === 'string' ? req.body.description.trim() : '',
      category: typeof req.body.category === 'string' ? req.body.category.trim() : '',
      image: imageUrl,
    });
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// PATCH update a product (Admin)
app.patch('/api/products/:id', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const updates = {};
    if (typeof req.body.title === 'string') updates.title = req.body.title.trim();
    if (req.body.price !== undefined) {
      const price = Number.parseFloat(req.body.price);
      if (!Number.isNaN(price)) updates.price = price;
    }
    if (typeof req.body.description === 'string') updates.description = req.body.description.trim();
    if (typeof req.body.category === 'string') updates.category = req.body.category.trim();
    if (req.file) {
      updates.image = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    }
    if (Object.keys(updates).length == 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    const updated = await Product.findByIdAndUpdate(
      req.params.id,
      updates,
      { returnDocument: 'after' }
    );
    if (!updated) return res.status(404).json({ error: 'Product not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// DELETE product (Admin Only)
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// POST create an order (User/Admin)
app.post('/api/orders', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const dateStr =
      `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`;
    const count = await Order.countDocuments({ orderCode: new RegExp(`^ORD-${dateStr}-`) });
    const orderCode = `ORD-${dateStr}-${String(count + 1).padStart(6, '0')}`;
    const newOrder = new Order({
      ...req.body,
      orderCode,
      customerName: req.user?.name?.trim() || req.user?.username || '',
      userId: req.userId,
      status: 0,
      statusHistory: [
        {
          status: 0,
          changedBy: req.userId,
        },
      ],
    });
    await newOrder.save();
    res.status(201).json({ message: 'Order placed successfully', order: newOrder });
  } catch (err) {
    res.status(500).json({ error: 'Failed to place order' });
  }
});

// GET orders (Admin can view all, User sees only their own)
app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === 'admin') {
      query = req.query.userId ? { userId: req.query.userId } : {};
    } else {
      query = { userId: req.userId };
    }
    const orders = await Order.find(query).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// PATCH update order details (Admin or Owner)
app.patch('/api/orders/:id', requireAuth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    const isOwner = order.userId == req.userId;
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not allowed to edit this order' });
    }

    const updates = {};
    if (typeof req.body.customerName === 'string') updates.customerName = req.body.customerName.trim();
    if (typeof req.body.companyName === 'string') updates.companyName = req.body.companyName.trim();
    if (typeof req.body.houseNumber === 'string') updates.houseNumber = req.body.houseNumber.trim();
    if (typeof req.body.addressDetail === 'string') updates.addressDetail = req.body.addressDetail.trim();
    if (typeof req.body.shippingAddress === 'string') updates.shippingAddress = req.body.shippingAddress.trim();
    if (Array.isArray(req.body.productDetails)) updates.productDetails = req.body.productDetails;

    if (req.body.quantity != null) {
      const qty = typeof req.body.quantity === 'number'
        ? req.body.quantity
        : parseInt(req.body.quantity, 10);
      if (!Number.isNaN(qty)) updates.quantity = qty;
    }
    if (req.body.totalAmount != null) {
      const total = typeof req.body.totalAmount === 'number'
        ? req.body.totalAmount
        : parseFloat(req.body.totalAmount);
      if (!Number.isNaN(total)) updates.totalAmount = total;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    Object.assign(order, updates);
    await order.save();
    res.json({ message: 'Order updated', order });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// PATCH update order status (Admin or Owner)
app.patch('/api/orders/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body;
  const statusInt = typeof status === 'number' ? status : parseInt(status ?? '', 10);
  if (statusInt == null || statusInt < 0 || statusInt > 6) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const isAdmin = req.user?.role == 'admin';
    const isOwner = order.userId == req.userId;
    if (!isAdmin) {
      if (!isOwner) return res.status(403).json({ error: 'Forbidden' });
      if (statusInt != 4) return res.status(403).json({ error: 'User can only cancel order' });
    }

    if (order.status !== statusInt) {
      order.status = statusInt;
      order.statusHistory = order.statusHistory || [];
      order.statusHistory.push({
        status: statusInt,
        changedBy: req.userId || '',
        changedAt: new Date(),
      });
      await order.save();
    }
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Start Server after DB is ready
const startServer = async () => {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 20000,
      connectTimeoutMS: 20000,
    });
    console.log('✅ Connected to MongoDB Atlas');
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 SStar Backend Server running at http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  }
};

startServer();
