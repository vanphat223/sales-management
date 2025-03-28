const express = require('express'); 
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Lấy từ .env hoặc dùng mặc định

// Middleware xác thực token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('Không có token trong yêu cầu');
    return res.status(401).json({ error: 'Yêu cầu đăng nhập' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token không hợp lệ:', err.message);
      return res.status(403).json({ error: 'Token không hợp lệ' });
    }
    req.user = user;
    next();
  });
};

// API đăng ký
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Thiếu thông tin bắt buộc' });
  }

  try {
    const checkQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
    db.query(checkQuery, [username, email], async (err, results) => {
      if (err) {
        console.error('Lỗi khi kiểm tra người dùng:', err);
        return res.status(500).json({ error: 'Lỗi server' });
      }
      if (results.length > 0) {
        return res.status(400).json({ error: 'Username hoặc email đã tồn tại' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertQuery = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
      db.query(insertQuery, [username, hashedPassword, email], (err, result) => {
        if (err) {
          console.error('Lỗi khi đăng ký:', err);
          return res.status(500).json({ error: 'Lỗi server khi đăng ký' });
        }
        console.log(`Đăng ký thành công cho ${username}`);
        res.status(201).json({ message: 'Đăng ký thành công' });
      });
    });
  } catch (err) {
    console.error('Lỗi server:', err);
    res.status(500).json({ error: 'Lỗi server: ' + err.message });
  }
});

// API đăng nhập
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Thiếu thông tin bắt buộc' });
  }

  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error('Lỗi khi đăng nhập:', err);
      return res.status(500).json({ error: 'Lỗi server' });
    }
    if (results.length === 0) {
      return res.status(400).json({ error: 'Username không tồn tại' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'Mật khẩu không đúng' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    console.log(`Đăng nhập thành công cho ${username}`);
    res.json({ token, username: user.username });
  });
});

// --- API cho Products ---
// Lấy danh sách sản phẩm
app.get('/api/products', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM products';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Lỗi khi lấy danh sách sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi lấy danh sách sản phẩm' });
    }
    const products = results.map(product => ({
      id: product.id,
      name: product.name,
      price: parseFloat(product.price),
      quantity: product.quantity
    }));
    res.json(products);
  });
});

// API tìm kiếm sản phẩm
app.get('/api/products/search', authenticateToken, (req, res) => {
  const searchQuery = req.query.q;
  if (!searchQuery) {
    return res.status(400).json({ error: 'Vui lòng nhập từ khóa tìm kiếm' });
  }
  const sql = 'SELECT * FROM products WHERE name LIKE ? OR description LIKE ?';
  const values = [`%${searchQuery}%`, `%${searchQuery}%`];

  db.query(sql, values, (err, results) => {
    if (err) {
      console.error('Lỗi truy vấn tìm kiếm sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi tìm kiếm sản phẩm' });
    }
    res.json(results);
  });
});

// Lấy thông tin một sản phẩm
app.get('/api/products/:id', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM products WHERE id = ?';
  db.query(query, [req.params.id], (err, results) => {
    if (err) {
      console.error('Lỗi khi lấy sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi lấy thông tin sản phẩm' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
    }
    const product = results[0];
    res.json({
      id: product.id,
      name: product.name,
      price: parseFloat(product.price),
      quantity: product.quantity
    });
  });
});

// Thêm sản phẩm
app.post('/api/products', authenticateToken, (req, res) => {
  const { name, price, quantity } = req.body;
  if (!name || price === undefined || quantity === undefined) {
    return res.status(400).json({ error: 'Thiếu thông tin bắt buộc' });
  }
  if (typeof price !== 'number' || price < 0 || typeof quantity !== 'number' || quantity < 0) {
    return res.status(400).json({ error: 'Giá và số lượng phải là số không âm' });
  }

  const query = 'INSERT INTO products (name, price, quantity) VALUES (?, ?, ?)';
  db.query(query, [name, price, quantity], (err, result) => {
    if (err) {
      console.error('Lỗi khi thêm sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi thêm sản phẩm' });
    }
    console.log(`Đã thêm sản phẩm: ${name}`);
    res.status(201).json({ id: result.insertId, name, price: parseFloat(price), quantity });
  });
});

// Sửa sản phẩm
app.put('/api/products/:id', authenticateToken, (req, res) => {
  const { name, price, quantity } = req.body;
  if (!name || price === undefined || quantity === undefined) {
    return res.status(400).json({ error: 'Thiếu thông tin bắt buộc' });
  }
  if (typeof price !== 'number' || price < 0 || typeof quantity !== 'number' || quantity < 0) {
    return res.status(400).json({ error: 'Giá và số lượng phải là số không âm' });
  }

  const query = 'UPDATE products SET name = ?, price = ?, quantity = ? WHERE id = ?';
  db.query(query, [name, price, quantity, req.params.id], (err, result) => {
    if (err) {
      console.error('Lỗi khi sửa sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi sửa sản phẩm' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
    }
    console.log(`Đã sửa sản phẩm ID: ${req.params.id}`);
    res.json({ id: req.params.id, name, price: parseFloat(price), quantity });
  });
});

// Xóa sản phẩm
app.delete('/api/products/:id', authenticateToken, (req, res) => {
  const query = 'DELETE FROM products WHERE id = ?';
  db.query(query, [req.params.id], (err, result) => {
    if (err) {
      console.error('Lỗi khi xóa sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi xóa sản phẩm' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Sản phẩm không tồn tại' });
    }
    console.log(`Đã xóa sản phẩm ID: ${req.params.id}`);
    res.json({ message: 'Xóa sản phẩm thành công' });
  });
});

// --- API cho Orders ---
// Lấy danh sách đơn hàng
app.get('/api/orders', authenticateToken, (req, res) => {
  const query = `
    SELECT o.*, oi.product_id, oi.quantity 
    FROM orders o 
    LEFT JOIN order_items oi ON o.id = oi.order_id
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error('Lỗi khi lấy danh sách đơn hàng:', err);
      return res.status(500).json({ error: 'Lỗi server khi lấy danh sách đơn hàng' });
    }
    const orders = [];
    results.forEach(row => {
      let order = orders.find(o => o.id === row.id);
      if (!order) {
        order = {
          id: row.id,
          customer_name: row.customer_name,
          total_price: parseFloat(row.total_price),
          status: row.status,
          created_at: row.created_at,
          items: []
        };
        orders.push(order);
      }
      if (row.product_id) {
        order.items.push({ product_id: row.product_id, quantity: row.quantity });
      }
    });
    res.json(orders);
  });
});

// Tạo đơn hàng
app.post('/api/orders', authenticateToken, (req, res) => {
  const { customer_name, products } = req.body;
  if (!customer_name || !Array.isArray(products) || products.length === 0) {
    console.log('Dữ liệu đầu vào không hợp lệ:', req.body);
    return res.status(400).json({ error: 'Thiếu thông tin bắt buộc hoặc danh sách sản phẩm không hợp lệ' });
  }

  db.query('SELECT id, name, price, quantity FROM products WHERE id IN (?)', [products.map(p => p.product_id)], (err, result) => {
    if (err) {
      console.error('Lỗi khi kiểm tra sản phẩm:', err);
      return res.status(500).json({ error: 'Lỗi server khi kiểm tra sản phẩm' });
    }

    let total_price = 0;
    for (let p of products) {
      if (!p.product_id || !p.quantity || p.quantity <= 0) {
        return res.status(400).json({ error: 'Sản phẩm hoặc số lượng không hợp lệ' });
      }
      const product = result.find(r => r.id === p.product_id);
      if (!product) {
        return res.status(400).json({ error: `Sản phẩm ID ${p.product_id} không tồn tại` });
      }
      if (product.quantity < p.quantity) {
        return res.status(400).json({ error: `Sản phẩm ${product.name} không đủ tồn kho` });
      }
      total_price += parseFloat(product.price) * p.quantity;
    }

    db.query('INSERT INTO orders (customer_name, total_price) VALUES (?, ?)', [customer_name, total_price], (err, orderResult) => {
      if (err) {
        console.error('Lỗi khi tạo đơn hàng:', err);
        return res.status(500).json({ error: 'Lỗi server khi tạo đơn hàng' });
      }
      const orderId = orderResult.insertId;

      const items = products.map(p => [orderId, p.product_id, p.quantity]);
      db.query('INSERT INTO order_items (order_id, product_id, quantity) VALUES ?', [items], (err) => {
        if (err) {
          console.error('Lỗi khi thêm sản phẩm vào đơn hàng:', err);
          return res.status(500).json({ error: 'Lỗi server khi thêm sản phẩm vào đơn hàng' });
        }

        // Cập nhật tồn kho
        products.forEach(p => {
          db.query('UPDATE products SET quantity = quantity - ? WHERE id = ?', [p.quantity, p.product_id], (err) => {
            if (err) console.error(`Lỗi khi cập nhật tồn kho cho sản phẩm ${p.product_id}:`, err);
          });
        });

        console.log(`Đã tạo đơn hàng ID: ${orderId}`);
        res.status(201).json({ id: orderId, customer_name, total_price: parseFloat(total_price), status: 'pending', items });
      });
    });
  });
});

// Sửa trạng thái đơn hàng
app.put('/api/orders/:id', authenticateToken, (req, res) => {
  const { status } = req.body;
  if (!status || !['pending', 'completed', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Trạng thái không hợp lệ' });
  }

  const query = 'UPDATE orders SET status = ? WHERE id = ?';
  db.query(query, [status, req.params.id], (err, result) => {
    if (err) {
      console.error('Lỗi khi sửa trạng thái đơn hàng:', err);
      return res.status(500).json({ error: 'Lỗi server khi sửa trạng thái đơn hàng' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Đơn hàng không tồn tại' });
    }
    console.log(`Đã sửa trạng thái đơn hàng ID: ${req.params.id} thành ${status}`);
    res.json({ id: req.params.id, status });
  });
});

// Xóa đơn hàng
app.delete('/api/orders/:id', authenticateToken, (req, res) => {
  db.query('SELECT product_id, quantity FROM order_items WHERE order_id = ?', [req.params.id], (err, items) => {
    if (err) {
      console.error('Lỗi khi lấy sản phẩm trong đơn hàng:', err);
      return res.status(500).json({ error: 'Lỗi server khi lấy sản phẩm trong đơn hàng' });
    }

    // Hoàn lại tồn kho
    items.forEach(item => {
      db.query('UPDATE products SET quantity = quantity + ? WHERE id = ?', [item.quantity, item.product_id], (err) => {
        if (err) console.error(`Lỗi khi hoàn tồn kho cho sản phẩm ${item.product_id}:`, err);
      });
    });

    const query = 'DELETE FROM orders WHERE id = ?';
    db.query(query, [req.params.id], (err, result) => {
      if (err) {
        console.error('Lỗi khi xóa đơn hàng:', err);
        return res.status(500).json({ error: 'Lỗi server khi xóa đơn hàng' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Đơn hàng không tồn tại' });
      }
      console.log(`Đã xóa đơn hàng ID: ${req.params.id}`);
      res.json({ message: 'Xóa đơn hàng thành công' });
    });
  });
});

// Khởi động server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
