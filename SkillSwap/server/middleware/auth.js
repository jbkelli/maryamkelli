// server/middleware/auth.js
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Protect routes - verify JWT
const protect = async (req, res, next) => {
  try {
    // 1) Get the token from the request headers
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      // Format: "Bearer <actual_token>"
      token = req.headers.authorization.split(' ')[1];
    }

    // 2) Check if token exists
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // 3) Verify the token
    // jwt.verify is callback-based. promisify converts it to a promise-based function.
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 4) Check if the user still exists (a token might be valid but user was deleted)
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token does no longer exist.'
      });
    }

    // 5) Grant access to the protected route
    // Attach the user data to the request object.
    // This will be available in the next middleware/controller function.
    req.user = currentUser;
    next(); // Call the next middleware/controller

  } catch (err) {
    res.status(401).json({ status: 'fail', message: 'Invalid token.' });
  }
};

module.exports = { protect };