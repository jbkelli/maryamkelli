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
    // Debug logs
    console.log('Protect middleware: received token:', token);
    console.log('Protect middleware: JWT_SECRET:', process.env.JWT_SECRET);

    // 2) Check if token exists
    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // 3) Verify the token
    try {
      const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
      console.log('Protect middleware: decoded token:', decoded);

      // 4) Check if the user still exists (a token might be valid but user was deleted)
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return res.status(401).json({
          status: 'fail',
          message: 'The user belonging to this token does no longer exist.'
        });
      }

      // 5) Grant access to the protected route
      req.user = currentUser;
      next();
    } catch (verifyErr) {
      console.error('Protect middleware: JWT verification error:', verifyErr);
      return res.status(401).json({
        status: 'fail',
        message: verifyErr.message || 'Invalid token.'
      });
    }
  } catch (err) {
    console.error('Protect middleware: General error:', err);
    return res.status(401).json({
      status: 'fail',
      message: err.message || 'Invalid token.'
    });
  }
};

module.exports = { protect };