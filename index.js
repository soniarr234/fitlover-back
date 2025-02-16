const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Crear un pool de conexiones para despliegue
const pool = mysql.createPool({
    host: process.env.MYSQL_ADDON_HOST,
    user: process.env.MYSQL_ADDON_USER,
    password: process.env.MYSQL_ADDON_PASSWORD,
    database: process.env.MYSQL_ADDON_DB,
    port: process.env.MYSQL_ADDON_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: false
    }
});

/*
// Crear un pool de conexiones para produccion
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.MYSQL_ADDON_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    ssl: {
        rejectUnauthorized: false
    }
});
*/
// Función para manejar errores de conexión
pool.on('error', (err) => {
    console.error('Error en la conexión con la base de datos:', err);
});

// Ruta para mantener vivo el backend en Render
app.get('/ping', (req, res) => {
    res.send('pong');
});

// Ruta para registrar un usuario
app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        const [result] = await pool.promise().query(
            'INSERT INTO usuarios (nombre, email, password_hash) VALUES (?, ?, ?)',
            [nombre, email, hashedPassword]
        );
        res.json({ message: 'Usuario registrado' });
    } catch (err) {
        res.status(500).json(err);
    }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await pool.promise().query(
            'SELECT * FROM usuarios WHERE email = ?',
            [email]
        );

        if (users.length === 0) return res.status(401).json({ message: 'Usuario no encontrado' });

        const isValid = await bcrypt.compare(password, users[0].password_hash);
        if (!isValid) return res.status(401).json({ message: 'Contraseña incorrecta' });

        const token = jwt.sign(
            { id: users[0].id, nombre: users[0].nombre, email: users[0].email },
            'secreto',
            { expiresIn: '1h' }
        );

        res.json({ token, nombre: users[0].nombre, email: users[0].email });
    } catch (err) {
        res.status(500).json(err);
    }
});

// Ruta para obtener el usuario autenticado
app.get('/usuario', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const [results] = await pool.promise().query(
            'SELECT nombre, email FROM usuarios WHERE id = ?',
            [decoded.id]
        );

        if (results.length === 0) return res.status(404).json({ message: "Usuario no encontrado" });

        res.json(results[0]);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener el usuario" });
    }
});

// Ruta para obtener todos los ejercicios
app.get('/ejercicios', async (req, res) => {
    try {
        const [results] = await pool.promise().query('SELECT * FROM ejercicios');
        res.json(results);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Ruta para agregar un ejercicio
app.post('/ejercicios', async (req, res) => {
    const { nombre, musculos, descripcion, observaciones, video_o_imagen_url } = req.body;

    try {
        const [result] = await pool.promise().query(
            'INSERT INTO ejercicios (nombre, musculos, descripcion, observaciones, video_o_imagen_url) VALUES (?, ?, ?, ?, ?)',
            [nombre, musculos, descripcion, observaciones, video_o_imagen_url]
        );

        res.status(201).json({ message: 'Ejercicio creado con éxito', id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear el ejercicio' });
    }
});

// Ruta para actualizar las observaciones de un ejercicio
app.put('/ejercicios/:id', async (req, res) => {
    const { id } = req.params;
    const { observaciones } = req.body;

    try {
        const [result] = await pool.promise().query(
            'UPDATE ejercicios SET observaciones = ? WHERE id = ?',
            [observaciones, id]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Observaciones actualizadas con éxito' });
        } else {
            res.status(404).json({ message: 'Ejercicio no encontrado' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar las observaciones' });
    }
});

// Ruta para crear una rutina
app.post('/rutinas', async (req, res) => {
    const { nombre } = req.body;
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const [result] = await pool.promise().query(
            'INSERT INTO rutinas (nombre, usuario_id) VALUES (?, ?)',
            [nombre, decoded.id]
        );

        res.status(201).json({ message: "Rutina creada con éxito", id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: "Error al crear la rutina" });
    }
});

// Ruta para obtener todas las rutinas del usuario autenticado
app.get('/rutinas', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const [results] = await pool.promise().query(
            'SELECT * FROM rutinas WHERE usuario_id = ?',
            [decoded.id]
        );

        res.json(results);
    } catch (error) {
        res.status(500).json({ message: "Error al obtener las rutinas" });
    }
});

// Ruta para añadir un ejercicio a una rutina
app.post('/rutina_ejercicios', async (req, res) => {
    const { rutina_id, ejercicio_id } = req.body;
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        await pool.promise().query(
            'INSERT INTO rutina_ejercicios (rutina_id, ejercicio_id) VALUES (?, ?)',
            [rutina_id, ejercicio_id]
        );

        res.status(201).json({ message: 'Ejercicio añadido a la rutina con éxito' });
    } catch (error) {
        res.status(500).json({ message: "Error al agregar el ejercicio a la rutina" });
    }
});

app.get('/rutina_ejercicios/:rutina_id', async (req, res) => {
    const { rutina_id } = req.params;

    pool.query(
        'SELECT e.* FROM ejercicios e INNER JOIN rutina_ejercicios re ON e.id = re.ejercicio_id WHERE re.rutina_id = ?', 
        [rutina_id], 
        (err, results) => {
            if (err) return res.status(500).json(err);
            res.json(results); // Devuelve los ejercicios de la rutina
        }
    );
});

app.get('/rutinas/:id', async (req, res) => {
    const { id } = req.params;
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const usuario_id = decoded.id;

        pool.query('SELECT * FROM rutinas WHERE id = ? AND usuario_id = ?', [id, usuario_id], (err, results) => {
            if (err) return res.status(500).json({ message: 'Error al obtener la rutina' });
            if (results.length === 0) return res.status(404).json({ message: 'Rutina no encontrada' });
            res.json(results[0]); // Devuelve la rutina con ese ID
        });

    } catch (error) {
        console.error("Error al obtener la rutina:", error);
        res.status(500).json({ message: "Error al obtener la rutina" });
    }
});

setInterval(() => {
    fetch("https://fitlover-back.onrender.com/ping")
      .then(() => console.log("Manteniendo vivo el backend"))
      .catch((err) => console.error("Error en el keep-alive", err));
  }, 5 * 60 * 1000); // Cada 5 minutos

// Iniciar el servidor
const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => console.log(`Backend corriendo en el puerto ${PORT}`));
