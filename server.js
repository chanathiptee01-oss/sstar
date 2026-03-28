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
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

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
    let products = await Product.find({});
    
    // Seed initial products if database is empty
    if (products.length === 0) {
      const initialProducts = [
        {
          title: "SStar Premium T-Shirt",
          price: 29.99,
          description: "High quality cotton t-shirt with SStar logo.",
          category: "clothing",
          image: "https://fakestoreapi.com/img/71-3HjGNDUL._AC_SY879._SX._UX._SY._UY_.jpg"
        },
        {
          title: "SStar Leather Jacket",
          price: 129.99,
          description: "Premium leather jacket for a sleek modern look.",
          category: "clothing",
          image: "https://fakestoreapi.com/img/81XH0e8fefL._AC_UY879_.jpg"
        },
        {
          title: "SStar Gold Watch",
          price: 299.99,
          description: "Elegant luxury watch with precise movement.",
          category: "accessories",
          image: "https://fakestoreapi.com/img/71pWzhdJNwL._AC_UL640_QL65_ML3_.jpg"
        },
        {
          title: "SStar Modern Backpack",
          price: 59.99,
          description: "Spacious and comfortable backpack for everyday use.",
          category: "accessories",
          image: "https://fakestoreapi.com/img/81fPKd-2AYL._AC_SL1500_.jpg"
        }
      ];
      await Product.insertMany(initialProducts);
      products = await Product.find({});
    }

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

    // First user is automatically admin for convenience
    const count = await User.countDocuments();
    const role = count === 0 ? 'admin' : 'user';

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

// POST add a new product (Admin)
app.post('/api/products', async (req, res) => {
  try {
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// POST create an order
app.post('/api/orders', async (req, res) => {
  try {
    const newOrder = new Order(req.body);
    await newOrder.save();
    res.status(201).json({ message: 'Order placed successfully', order: newOrder });
  } catch (err) {
    res.status(500).json({ error: 'Failed to place order' });
  }
});

// GET orders (Accepts query param ?userId=xyz to filter, else returns all for admin)
app.get('/api/orders', async (req, res) => {
  try {
    const query = req.query.userId ? { userId: req.query.userId } : {};
    const orders = await Order.find(query).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SStar Backend Server running at http://localhost:${PORT}`);
});
