const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
require('dotenv').config();


const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host: process.env.MYSQL_ADDON_HOST,
    user: process.env.MYSQL_ADDON_USER,
    password: process.env.MYSQL_ADDON_PASSWORD,
    database: process.env.MYSQL_ADDON_DB,
    port: process.env.MYSQL_ADDON_PORT,
    ssl: {
        rejectUnauthorized: false
    }
});

app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO usuarios (nombre, email, password_hash) VALUES (?, ?, ?)', 
        [nombre, email, hashedPassword], 
        (err, result) => {
            if (err) return res.status(500).json(err);
            res.json({ message: 'Usuario registrado' });
        }
    );
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, users) => {
        if (err) return res.status(500).json(err);
        if (users.length === 0) return res.status(401).json({ message: 'Usuario no encontrado' });

        const isValid = await bcrypt.compare(password, users[0].password_hash);
        if (!isValid) return res.status(401).json({ message: 'Contraseña incorrecta' });

        // Generar el token con más datos
        const token = jwt.sign(
            { id: users[0].id, nombre: users[0].nombre, email: users[0].email },
            'secreto',
            { expiresIn: '1h' }
        );

        res.json({ token, nombre: users[0].nombre, email: users[0].email });
    });
});

app.get('/usuario', (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const usuario_id = decoded.id;

        db.query('SELECT nombre, email FROM usuarios WHERE id = ?', [usuario_id], (err, results) => {
            if (err) return res.status(500).json({ message: "Error al obtener el usuario" });
            if (results.length === 0) return res.status(404).json({ message: "Usuario no encontrado" });

            console.log("Usuario autenticado:", results[0].nombre, "-", results[0].email);
            res.json(results[0]); // Retorna el nombre y correo
        });

    } catch (error) {
        console.error("Error al obtener el usuario:", error);
        res.status(500).json({ message: "Error al obtener el usuario" });
    }
});


app.get('/ejercicios', (req, res) => {
    db.query('SELECT * FROM ejercicios', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results); // Incluye musculos, descripcion, observaciones y video_o_imagen_url
    });
});

app.post('/ejercicios', async (req, res) => {
    const { nombre, musculos, descripcion, observaciones, video_o_imagen_url } = req.body;

    try {
        const [result] = await db.promise().query(
            'INSERT INTO ejercicios (nombre, musculos, descripcion, observaciones, video_o_imagen_url) VALUES (?, ?, ?, ?, ?)',
            [nombre, musculos, descripcion, observaciones, video_o_imagen_url]
        );

        res.status(201).json({ message: 'Ejercicio creado con éxito', id: result.insertId });
    } catch (error) {
        console.error('Error al crear el ejercicio:', error);
        res.status(500).json({ message: 'Error al crear el ejercicio' });
    }
});


// Ruta para actualizar las observaciones de un ejercicio
app.put('/ejercicios/:id', async (req, res) => {
    const { id } = req.params;
    const { observaciones } = req.body; // Recibe las observaciones desde el frontend

    try {
        // Actualiza las observaciones en la base de datos
        const [result] = await db.promise().query(
            'UPDATE ejercicios SET observaciones = ? WHERE id = ?',
            [observaciones, id]
        );

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Observaciones actualizadas con éxito' });
        } else {
            res.status(404).json({ message: 'Ejercicio no encontrado' });
        }
    } catch (error) {
        console.error('Error al actualizar las observaciones:', error);
        res.status(500).json({ message: 'Error al actualizar las observaciones' });
    }
});

app.post('/rutinas', async (req, res) => {
    const { nombre } = req.body;
    const token = req.headers.authorization?.split(" ")[1]; // Extrae el token

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        // Decodificar el token para obtener el ID del usuario
        const decoded = jwt.verify(token, 'secreto');
        const usuario_id = decoded.id;

        // Insertar la rutina en la base de datos
        const [result] = await db.promise().query(
            'INSERT INTO rutinas (nombre, usuario_id) VALUES (?, ?)',
            [nombre, usuario_id]
        );

        res.status(201).json({ message: "Rutina creada con éxito", id: result.insertId });
    } catch (error) {
        console.error("Error al crear la rutina:", error);
        res.status(500).json({ message: "Error al crear la rutina" });
    }
});

app.get('/rutinas', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; // Extrae el token

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        const decoded = jwt.verify(token, 'secreto');
        const usuario_id = decoded.id;

        db.query('SELECT * FROM rutinas WHERE usuario_id = ?', [usuario_id], (err, results) => {
            if (err) return res.status(500).json({ message: 'Error al obtener las rutinas' });
            res.json(results); // Retorna las rutinas
        });

    } catch (error) {
        console.error("Error al obtener rutinas:", error);
        res.status(500).json({ message: "Error al obtener las rutinas" });
    }
});

app.post('/rutina_ejercicios', async (req, res) => {
    const { rutina_id, ejercicio_id } = req.body;
    const token = req.headers.authorization?.split(" ")[1]; // Extrae el token

    if (!token) return res.status(401).json({ message: "No autorizado" });

    try {
        // Decodificar el token para obtener el ID del usuario
        const decoded = jwt.verify(token, 'secreto');
        const usuario_id = decoded.id;

        // Verifica si el ejercicio ya está añadido a la rutina
        const [existingExercise] = await db.promise().query(
            'SELECT * FROM rutina_ejercicios WHERE rutina_id = ? AND ejercicio_id = ?',
            [rutina_id, ejercicio_id]
        );

        if (existingExercise.length > 0) {
            return res.status(400).json({ message: 'Este ejercicio ya está en la rutina' });
        }

        // Insertar el ejercicio en la rutina
        const [result] = await db.promise().query(
            'INSERT INTO rutina_ejercicios (rutina_id, ejercicio_id) VALUES (?, ?)',
            [rutina_id, ejercicio_id]
        );

        res.status(201).json({ message: 'Ejercicio añadido a la rutina con éxito' });
    } catch (error) {
        console.error("Error al agregar el ejercicio a la rutina:", error);
        res.status(500).json({ message: "Error al agregar el ejercicio a la rutina" });
    }
});


app.get('/rutina_ejercicios/:rutina_id', (req, res) => {
    const { rutina_id } = req.params;
    db.query(
        `SELECT e.* FROM ejercicios e
         INNER JOIN rutina_ejercicios re ON e.id = re.ejercicio_id
         WHERE re.rutina_id = ?`, 
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

        db.query('SELECT * FROM rutinas WHERE id = ? AND usuario_id = ?', [id, usuario_id], (err, results) => {
            if (err) return res.status(500).json({ message: 'Error al obtener la rutina' });
            if (results.length === 0) return res.status(404).json({ message: 'Rutina no encontrada' });
            res.json(results[0]); // Devuelve la rutina con ese ID
        });

    } catch (error) {
        console.error("Error al obtener la rutina:", error);
        res.status(500).json({ message: "Error al obtener la rutina" });
    }
});



app.listen(3000, () => console.log('Backend corriendo en el puerto 3000'));