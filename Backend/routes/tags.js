import express from 'express';
import pool from '../db.js';
const router = express.Router();

/*GETS THE TAGS FOR A COURSE OR A REVIEW OR ALL THE TAGS.*/
router.get('/', async (req,res)=>{
    const {course_id,review_id} = req.query;
    try {
        let rows;
        if(course_id && review_id){
            [rows]= await pool.query(`
                SELECT * FROM tags 
                WHERE course_id= ? AND review_id= ?`,[course_id,review_id])
        }
        else if(course_id && !review_id){
            [rows] = await pool.query(`
                SELECT * FROM tags 
                WHERE course_id= ?`,[course_id])
        }
        else if(!course_id && review_id){
            [rows]= await pool.query(`
                SELECT * FROM tags 
                WHERE review_id= ?`,[review_id])
        }
        else{
            [rows]= await pool.query(`
                SELECT * FROM tags`)
        }
        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching tags :', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

export default router