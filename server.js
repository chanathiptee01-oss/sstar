require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
if (!MONGO_URI) {
  console.error('❌ MONGO_URI is not set. Please configure it in the environment.');
  process.exit(1);
}

// --- Schemas & Models ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // Should be hashed in prod
  role: { type: String, default: 'user', enum: ['user', 'admin'] }
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  title: String,
  price: Number,
  description: String,
  category: String,
  image: String
});
const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  customerName: { type: String, required: true },
  productDetails: { type: Object, required: true },
  totalAmount: { type: Number, required: true },
  status: { type: String, default: 'Pending' },
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
    const products = await Product.find({});

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read products', details: err.message });
  }
});

// POST register user
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  
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

    const newUser = new User({ username, password: hashedPassword, role });
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

// POST add a new product (Admin)
app.post('/api/products', requireAdmin, async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// POST create an order (User/Admin)
app.post('/api/orders', requireAuth, async (req, res) => {
  try {
    const newOrder = new Order({
      ...req.body,
      userId: req.userId,
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
