import express from 'express';
import pool from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
const router = express.Router();
const jwt_secret = process.env.JWT_SECRET;

function authenticateToken(req,res,next){
    const token = req.cookies.token;
    //major change made here.->func different from authenticateToken from users.js
    if (token == null) {
        req.user = null;
        return next(); // Allow the request to continue even if there's no token
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

router.get('/',async (req,res)=>{
    const {
        page = 1,
        pageSize = 20,
        instructor,
        level,
        sortBy = 'title',
        order = 'asc',
        search,
        tags // Assuming `tags` is a comma-separated string in query parameters
    } = req.query;
    
    let query = "";
    const params = [];
    if (tags && tags.length>0) {
        const tagArray = tags.split(',');
        const placeholders = tagArray.map(() => '?').join(',');
        query += `
        SELECT 
            c.* 
        FROM 
            courses c 
            JOIN 
            tags t 
        ON 
            c.course_id = t.course_id 
        WHERE 
            t.tag IN (${placeholders})`;
        
        params.push(...tagArray);
        
        if (instructor) {
            query += ' AND c.instructor LIKE ?';
            params.push(`%${instructor}%`);
        }
        if (level) {
            query += ' AND c.level = ?';
            params.push(level);
        }
        if (search) {
            query += ' AND (c.title LIKE ? OR c.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
    }
    else{
        query += `
            SELECT * 
            FROM courses 
            WHERE 1=1`;
    
        if (instructor) {
            query += ` AND instructor LIKE ?`;
            params.push(`%${instructor}%`);
        }
        if (level) {
            query += ` AND level = ?`;
            params.push(level);
        }
        if (search) {
            query += ` AND (title LIKE ? OR description LIKE ?)`;
            params.push(`%${search}%`, `%${search}%`);
        }
    }

    query += ` ORDER BY ${sortBy} ${order.toUpperCase()}`;
    query += ` LIMIT ${parseInt(pageSize, 10)} OFFSET ${((page - 1) * pageSize)}`;
    try {
        const [rows] = await pool.query(query, params);
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching courses:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})


router.post('/add',authenticateToken,async (req,res)=>{
    const {
        title,
        description,
        website,
        instructor,
        level,
        is_paid,
        price,
        duration,
        overall_rating,
        number_of_reviews,
        generated_review,
        link,
        tags /*Array*/
    } = req.body;
    const course_id = uuidv4();
    const user_id = req.user;
    try {
        await pool.query(`INSERT INTO courses(
            course_id,
            user_id,
            title,
            description,
            website,
            instructor,
            level,
            is_paid,
            price,
            duration,
            overall_rating,
            number_of_reviews,
            generated_review,
            link) 
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [   
                course_id,
                user_id,
                title,
                description,
                website,
                instructor,
                level,
                is_paid,
                price,
                duration,
                overall_rating,
                number_of_reviews,
                generated_review,
                link
            ])
        
        for(let i=0;i<tags.length;i++){
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
                tags[i],
                course_id,
                null /*Here tag only belongs to only review*/
            ])
        }
        res.status(200).json({message: `Course Added Successfully with ID : ${course_id}`});
    } catch (err) {
        console.error('Error adding course :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

router.post('/explored_course',authenticateToken,async (req,res)=>{
    const {course_id}=req.body;
    const user_id = req.user;
    try {
        if(user_id){
            await pool.query(`
                INSERT INTO explored_courses(
                    user_id,
                    course_id
                ) 
                VALUES(?,?)`,
            [
                user_id,
                course_id
            ])

            /*The recommendation algo needs to be run and the result i.e; course_ids returned
            should be added to the recommended_courses after the old recommendations are removed.*/

            res.status(200).json({message: `Explored Course - ${course_id} Added Successfully`});
        }
        else res.status(200).json({message: "Guest User."})
    } catch (err) {
        console.error('Error adding explored course :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

router.get('/recommended_courses',authenticateToken,async (req,res)=>{
    const user_id = req.user;
    try {
        if(user_id){
            const [exp_rows] = await pool.query(`
                SELECT * 
                FROM explored_courses 
                WHERE user_id = ?`,
            [user_id])
            if(exp_rows.length > 5){
                //if atleast 5 courses are explored then the recommendations are shown. otherwise recommendations won't be reliable.
                const [rows] = await pool.query(`
                    SELECT 
                        c.*
                    FROM 
                        recommended_courses r join courses c 
                    ON 
                        r.course_id=c.course_id 
                    WHERE 
                        r.user_id = ? 
                    ORDER BY 
                        c.overall_rating desc 
                    LIMIT 10`,
                [user_id])
                res.status(200).json(rows);
                return;
            }
        }
        //for guest users,getting the top 10 courses.
        const [rows] = await pool.query(`
            SELECT * 
            FROM courses 
            ORDER BY overall_rating desc 
            LIMIT 10`
        )
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching recommended course :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

export default router