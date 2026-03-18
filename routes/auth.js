var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const authGuard = require('../middlewares/authGuard');
const privateKey = fs.readFileSync(path.join(__dirname, '../private.key'), 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69ba1ac66cb55cdee9341ad6"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send(error.message)
    }

})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return
        }
        if (bcrypt.compareSync(password, user.password)) {
            loginCount = 0;
            await user.save()

            let token = jwt.sign(
                { id: user._id, username: user.username }, 
                privateKey, 
                { algorithm: 'RS256', expiresIn: '1h' }
            );

            res.send({
                id: user._id,
                token: token
            });
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap sai"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }

})

router.get('/me', authGuard, async function(req, res, next) {
    // req.user đã được gán từ authGuard
    // Chú ý: Nên ẩn password trước khi trả về cho client
    let userInfo = req.user.toObject();
    delete userInfo.password;
    
    res.send(userInfo);
});

// API /changepassword (Yêu cầu đăng nhập)
router.post('/changepassword', authGuard, async function(req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;

        // 1. Validate newpassword cơ bản (bạn có thể custom thêm)
        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
        }

        let user = req.user;

        // 2. Kiểm tra mật khẩu cũ có đúng không
        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // 3. Hash mật khẩu mới và lưu lại
        let salt = bcrypt.genSaltSync(10);
        user.password = bcrypt.hashSync(newpassword, salt);
        await user.save();

        res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});


module.exports = router;