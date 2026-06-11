const express = require('express');
const cors = require('cors');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// 允許跨域 (CORS)，這裡先寫死您的前端 TOS 網址和本地測試網址
app.use(cors({ 
    origin: ['http://localhost:5173', 'https://offpeak-frontend.tos-cn-hongkong.bytepluses.com'], 
    credentials: true 
}));
app.use(express.json());
app.use(passport.initialize());

// ⚠️ 模擬數據庫 (實際項目請替換為 MongoDB/PostgreSQL)
const users = []; 

// 生成 JWT Token 輔助函數
const generateToken = (user) => {
    return jwt.sign(
        { id: user.id, email: user.email, role: user.role || 'user' },
        process.env.JWT_SECRET || 'offpeak_secret_key',
        { expiresIn: '7d' }
    );
};

// ==========================================
// 1. Membership (本地會員) 登錄策略
// ==========================================
passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
        try {
            const user = users.find(u => u.email === email);
            if (!user) return done(null, false, { message: '用戶不存在' });
            
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return done(null, false, { message: '密碼錯誤' });
            
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// ==========================================
// 2. Google Account 登錄策略
// ==========================================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
    try {
        let user = users.find(u => u.googleId === profile.id);
        if (!user) {
            user = {
                id: Date.now().toString(),
                googleId: profile.id,
                email: profile.emails[0].value,
                name: profile.displayName,
                avatar: profile.photos[0]?.value,
                role: 'user'
            };
            users.push(user);
        }
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

// ==========================================
// 3. API 路由 (Routes)
// ==========================================

// [Membership] 註冊
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (users.find(u => u.email === email)) return res.status(400).json({ msg: '該郵箱已註冊' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const newUser = { id: Date.now().toString(), email, password: hashedPassword, name, role: 'user' };
    users.push(newUser);
    
    res.status(201).json({ token: generateToken(newUser), user: { id: newUser.id, email, name } });
});

// [Membership] 登錄
app.post('/api/auth/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err || !user) return res.status(400).json({ msg: info?.message || '登錄失敗' });
        res.json({ token: generateToken(user), user: { id: user.id, email: user.email, name: user.name } });
    })(req, res, next);
});

// [Google] 發起 Google 登錄
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// [Google] Google 回調處理
app.get('/api/auth/google/callback', 
    passport.authenticate('google', { session: false, failureRedirect: 'https://offpeak-frontend.tos-cn-hongkong.bytepluses.com/login' }),
    (req, res) => {
        const token = generateToken(req.user);
        // 實際項目中，這裡會重定向回您的前端網址並帶上 token
        res.redirect(`https://offpeak-frontend.tos-cn-hongkong.bytepluses.com/auth/callback?token=${token}`);
    }
);

// 受保護的路由測試 (驗證 Token)
app.get('/api/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: '未授權' });
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'offpeak_secret_key');
        res.json({ user: decoded });
    } catch (err) {
        res.status(401).json({ msg: 'Token 無效' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Off-Peak Server running on port ${PORT}`));