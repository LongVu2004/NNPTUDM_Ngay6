const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const userModel = require('../schemas/users');

const publicKey = fs.readFileSync(path.join(__dirname, '../public.key'), 'utf8');

module.exports = async function(req, res, next) {
    try {
        let token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).send({ message: "Vui lòng đăng nhập" });
        }

        // Verify token bằng Public Key
        let decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        
        let user = await userModel.findById(decoded.id);
        if (!user) {
            return res.status(404).send({ message: "User không tồn tại" });
        }

        req.user = user; // Gắn thông tin user vào req để dùng ở các route sau
        next();
    } catch (error) {
        res.status(401).send({ message: "Token không hợp lệ hoặc đã hết hạn" });
    }
};