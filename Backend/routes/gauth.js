import express from 'express';
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import pool from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
dotenv.config();
const router = express.Router();

const google_client_id = process.env.GOOGLE_CLIENT_ID
const google_client_secret = process.env.GOOGLE_CLIENT_SECRET

// Configure session management
router.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
router.use(passport.initialize());
router.use(passport.session());

// Serialize user into the session
passport.serializeUser((user, done) => {
    done(null, user.user_id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await pool.query(`
            SELECT * 
            FROM users 
            WHERE user_id = ?`, 
        [id]);
        if (rows.length === 0) {
            return done(null, false);
        }
        done(null, rows[0]);
    } catch (err) {
        done(err, null);
    }
});

// Configure Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: google_client_id,
    clientSecret: google_client_secret,
    callbackURL: "/api/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    try {
        const [rows] = await pool.query(`
            SELECT * 
            FROM users 
            WHERE google_id = ?`, 
        [profile.id]);
        let user;
        if (rows.length > 0) {
            user = rows[0];
        } else {
            const user_id = uuidv4();
            await pool.query(`
                INSERT INTO users(
                    user_id, 
                    google_id, 
                    name, 
                    email) 
                VALUES (?, ?, ?, ?)`, 
            [
                user_id, 
                profile.id, 
                profile.displayName, 
                profile.emails[0].value
            ]);
            const [newUser] = await pool.query(`
                SELECT * 
                FROM users 
                WHERE user_id = ?`, 
            [user_id]);
            user = newUser[0];
        }

        // Create JWT
        const jwt_secret = process.env.JWT_SECRET;
        const token = jwt.sign({ userId: user.user_id }, jwt_secret, { expiresIn: '1d' });
        const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Update the user with the new token and expiry time
        await pool.query(`
            UPDATE users 
            SET token_expires_at = ?, last_login = ? 
            WHERE user_id = ?`, 
        [
            tokenExpiresAt, 
            new Date(), 
            user.user_id
        ]);

        // Pass user and token to the done callback
        done(null, { ...user, token });
    } catch (err) {
        done(err, null);
    }
}));

// Google OAuth login route
router.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth callback route
router.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Send the token in the response body
        res.status(200).json({ token: req.user.token });
    }
);

export default router;
