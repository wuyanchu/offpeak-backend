const express = require('express');
const cors = require('cors');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ⚠️ 關鍵配置 1：允許跨域 (請確保這裡包含了您的真實前端網址)
const allowedOrigins = [
  'http://localhost:5173',
  'https://offpeak-frontend.tos-cn-hongkong.bytepluses.com',
  'http://offpeak.duckdns.org' // 如果您使用了 DuckDNS，請保留或修改為您的真實域名
];

app.use(cors({ 
    origin: function(origin, callback) {
      // 允許沒有 origin 的請求 (例如 Postman 或某些伺服器間請求)
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true 
}));
app.use(express.json());
app.use(passport.initialize());

// ⚠️ 關鍵配置 2：定義您的前端和後端網址 (請務必修改為您真實的網址！)
// 如果您用的是 DuckDNS，請把 FRONTEND_URL 改為 'http://offpeak.duckdns.org'
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://offpeak-frontend.tos-cn-hongkong.bytepluses.com';
// 後端網址用於 Google OAuth 回調 (必須與 Google Console 中填寫的完全一致，包含 http/https 和 :5000)
const BACKEND_URL = process.env.BACKEND_URL || 'http://101.47.31.160:5000'; 

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
    // ⚠️ 關鍵配置 3：回調網址必須與 Google Cloud Console 中填寫的「一字不差」
    callbackURL: `${BACKEND_URL}/api/auth/google/callback`
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
// ⚠️ 關鍵配置 4：修復重定向，確保帶有 /?token= 並且指向正確的前端首頁
app.get('/api/auth/google/callback', 
    passport.authenticate('google', { session: false, failureRedirect: `${FRONTEND_URL}/` }),
    (req, res) => {
        const token = generateToken(req.user);
        // 這裡是解決「顯示文件列表」問題的終極修復！
        res.redirect(`${FRONTEND_URL}/?token=${token}`);
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