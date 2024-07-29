import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import pool from '../db.js';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();
const router = express.Router();

router.use(cookieParser());
const jwt_secret = process.env.JWT_SECRET;

router.post("/login",async (req,res)=>{
    try {
        const {username,password} = req.body;
        const [row] = await pool.query(`
            SELECT * 
            FROM users 
            WHERE username= ?`,
        [username]);

        if (row.length === 0) 
            return res.status(401).json({ error: 'Invalid username or password' });

        const user = row[0]
        const isMatch = await bcrypt.compare(password, user.password_hashed);
        if(!isMatch) 
            return res.status(401).json({ error: 'Invalid username or password' });
        
        const token = jwt.sign({ userId: user.user_id }, jwt_secret, { expiresIn: '1d' });
        const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await pool.query(`
            UPDATE users 
            SET token_expires_at=?, last_login=? 
            WHERE user_id=?`,
        [tokenExpiresAt,new Date(),user.user_id]);

        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
        res.status(200).json({ message: 'Logged in successfully' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: 'Internal server error' });
    }
})

router.post("/signup",async (req,res)=>{
    try {
        const {username,password,name,email} = req.body;
        const user_id = uuidv4();
        const hashedPassword = await bcrypt.hash(password, 10);
        const token = jwt.sign({ userId: user_id }, jwt_secret, { expiresIn: '1d' });
        const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        const [rows] = await pool.query(`
            SELECT * 
            FROM users 
            WHERE username = ?`,
        [username])

        if(rows.length>0){
            //409 Conflict
            return res.status(409).json({message: 'Username already exits.'})
        }

        await pool.query(`
            INSERT INTO users(
                user_id,
                username,
                password_hashed,
                name,
                email,
                token_expires_at,
                last_login) 
            VALUES(?,?,?,?,?,?,?)`,
        [
            user_id,
            username,
            hashedPassword,
            name,
            email,
            tokenExpiresAt,
            new Date()
        ]); 
        
        console.log(`User registered with UUID: ${user_id}`);
        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
        res.status(200).json({ message: 'Registered successfully' });
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: 'Internal server error' });
    }
})

function authenticateToken(req,res,next){
    const token = req.cookies.token;
    if (!token) return res.status(401).json({message: 'Authorisation Failed : Auth token not provided'}); // Unauthorized

    jwt.verify(token, jwt_secret, async (err, decoded) => {
        if (err){ 
            console.error('JWT verification error:', err);
            return res.status(403).json({message: 'Authorisation Failed : Forbidden Request'}); // Forbidden
        }

        // Retrieve the user's token expiry from the database
        try {
            const [rows] = await pool.query(`
                SELECT token_expires_at 
                FROM users 
                WHERE user_id = ?`,
            [decoded.userId]);

            if (rows.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            const tokenExpiresAt = new Date(rows[0].token_expires_at);
            if (tokenExpiresAt <= new Date()) {
                return res.status(401).json({ message: 'Token has expired' }); // Unauthorized
            }

            req.user = decoded.userId;
            next(); // Pass the execution to the next middleware or route handler
        } catch (dbErr) {
            console.error('Database error:', dbErr);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
}
router.get("/profile",authenticateToken,async (req,res)=>{
    try {
        const user_id = req.user
        const [rows] = await pool.query(`
            SELECT * 
            FROM users 
            WHERE user_id = ?`,
        [user_id])

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        const userProfile = rows[0]
        res.status(200).json({name: userProfile.name, email: userProfile.email})
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: 'Internal server error' });
    }
})

router.post("/logout", authenticateToken, async (req, res) => {
    try {
        const user_id = req.user;
        const tokenExpiresAt = new Date(0); // Set to epoch time, effectively making it expired

        await pool.query(`
            UPDATE users 
            SET token_expires_at=? 
            WHERE user_id=?`,
        [tokenExpiresAt, user_id]);

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router