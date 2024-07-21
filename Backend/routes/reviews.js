import express from 'express';
import pool from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
const router = express.Router();
const jwt_secret = process.env.JWT_SECRET;

function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    //major change made here.->func different from authenticateToken from users.js
    if (token == null){
        req.user = null;
        return next();
    }

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

// Get reviews by course ID
router.get('/',async (req,res)=>{
    const {course_id}=req.query;
    try {
        const [rows] = await pool.query(`
            SELECT * 
            FROM reviews 
            WHERE course_id = ?`,
        [course_id])
        res.status(200).json(rows)
    } catch (err) {
        console.error('Error fetching review :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

// Get reviews by user ID
router.get('/user',authenticateToken,async (req,res)=>{
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const [rows] = await pool.query(`
            SELECT * 
            FROM reviews 
            WHERE user_id = ?`,
        [req.user])
        res.status(200).json(rows)
    } catch (err) {
        console.error('Error fetching review :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

// Add a new review
router.post('/add',authenticateToken,async (req,res)=>{
    const {
        course_id,
        rating,
        review,
        skills_acquired, //send and store as comma seperated values.
        tags //Array
    }=req.body;

    const review_id = uuidv4()
    const user_id = req.user;

    try{
        await pool.query(`
            INSERT INTO reviews(
                review_id,
                course_id,
                user_id,
                rating,
                review,
                skills_acquired
            ) 
            VALUES(?,?,?,?,?,?)`,
        [
            review_id,
            course_id,
            user_id,
            rating,
            review,
            skills_acquired
        ])

        for (const tag of tags) {
            const tag_id = uuidv4()
            await pool.query(`
                INSERT INTO tags(
                tag_id,
                tag,
                course_id,
                review_id)
                VALUES(?,?,?,?)`,
            [
                tag_id,
                tag,
                course_id,
                review_id /*Here tag only belongs to only review*/
            ])
        }
        res.status(200).json({message: `Review Added Successfully with ID : ${review_id}`});
    } catch(err){
        console.error('Error adding review :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

export default router