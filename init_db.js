const mysql = require('mysql2/promise');
require('dotenv').config();

async function initDB() {
    console.log('🚀 Connecting to BytePlus RDS...');
    // 先不連接特定數據庫，以確保有最高權限創建數據庫
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT || 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD
    });

    try {
        console.log('📦 Creating database offpeak_db...');
        await connection.execute('CREATE DATABASE IF NOT EXISTS offpeak_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        
        console.log('🔄 Switching to offpeak_db and creating users table...');
        await connection.execute('USE offpeak_db');
        
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                password VARCHAR(255),
                name VARCHAR(255),
                google_id VARCHAR(255) UNIQUE,
                avatar TEXT,
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('🎉 Success! Database and Table are perfectly ready!');
    } catch (err) {
        console.error('❌ Error:', err.message);
    } finally {
        await connection.end();
    }
}

initDB();