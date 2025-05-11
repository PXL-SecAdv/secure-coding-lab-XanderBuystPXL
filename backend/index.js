const pg = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors')

const port=3000;

const pool = new pg.Pool({
    user: process.env.POSTGRES_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.POSTGRES_PASSWORD,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000
});

console.log("Connecting...:")

app.use(cors({
    origin: 'http://localhost:8080',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
}));
app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

app.post('/register', async (request, response) => {
    const { username, password } = request.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (user_name, password) VALUES ($1, $2)';
        const values = [username, hashedPassword];

        await pool.query(query, values);
        response.status(201).send('User registered successfully');
    } catch (error) {
        console.error('Error registering user', error.stack);
        response.status(500).send('Internal Server Error');
    }
});

app.get('/authenticate/:username/:password', async (request, response) => {
    const username = request.params.username;
    const password = request.params.password;

    const query = 'SELECT * FROM users WHERE user_name=$1';
    const values = [username];

    try {
        const results = await pool.query(query, values);
        if (results.rows.length > 0) {
            const user = results.rows[0];
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (isPasswordValid) {
                response.status(200).json({ message: 'Authentication successful' });
            } else {
                response.status(401).send('Invalid username or password');
            }
        } else {
            response.status(401).send('Invalid username or password');
        }
    } catch (error) {
        console.error('Error during authentication', error.stack);
        response.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
  console.log(`App running on port ${port}.`)
})

