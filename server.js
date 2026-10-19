require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.SECRET_KEY || "clave_secreta_inframen_2026";

app.use(cors());
app.use(express.json());

// Carpeta de imágenes (se crea si no existe, Git no sube carpetas vacías)
const carpetaUploads = path.join(__dirname, "uploads");
fs.mkdirSync(carpetaUploads, { recursive: true });
app.use("/uploads", express.static(carpetaUploads));

// Conexión dinámica: local (XAMPP) o nube (TiDB) según variables de entorno
const conexion = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "incidencias_escolares",
  port: process.env.DB_PORT || 3306,
  ssl: process.env.DB_HOST
    ? { minVersion: "TLSv1.2", rejectUnauthorized: true }
    : undefined,
  waitForConnections: true,
  connectionLimit: 5
});

// Configuración de almacenamiento para Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, carpetaUploads),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// ---------------- MIDDLEWARES ----------------

// Verificar JWT
const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ mensaje: "Token requerido" });
  try {
    const bearer = token.split(" ")[1] || token;
    const decoded = jwt.verify(bearer, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
};

// Exigir rol Admin
const soloAdmin = (req, res, next) => {
  if (req.usuario.rol !== "Admin") {
    return res.status(403).json({
      mensaje: "Acceso denegado. Se requieren permisos de Administrador."
    });
  }
  next();
};

// ---------------- AUTENTICACIÓN ----------------

// Registro de usuario
app.post("/registro", async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password) {
    return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)";
    conexion.query(sql, [nombre, email, hashedPassword, rol || "Usuario"], (error, resultado) => {
      if (error) return res.status(500).json(error);
      res.json({ mensaje: "Usuario registrado correctamente" });
    });
  } catch (e) {
    res.status(500).json({ mensaje: "Error al procesar el registro" });
  }
});

// Inicio de sesión
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM usuarios WHERE email = ?";
  conexion.query(sql, [email], async (error, resultado) => {
    if (error) return res.status(500).json(error);
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });

    const usuario = resultado[0];
    const passwordValida = await bcrypt.compare(password, usuario.password);
    if (!passwordValida) return res.status(401).json({ mensaje: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      mensaje: "Inicio de sesión exitoso",
      token,
      usuario: { id: usuario.id, nombre: usuario.nombre, email: usuario.email, rol: usuario.rol }
    });
  });
});

// Perfil del usuario autenticado
app.get("/perfil", verificarToken, (req, res) => {
  const usuarioId = req.usuario.id;
  const sql = "SELECT id, nombre, email, rol, fecha_creacion FROM usuarios WHERE id = ?";
  conexion.query(sql, [usuarioId], (error, resultado) => {
    if (error) return res.status(500).json(error);
    if (resultado.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });
    res.json(resultado[0]);
  });
});

// ---------------- INCIDENCIAS Y RECURSOS ----------------

// 1. Obtener categorías
app.get("/categorias", (req, res) => {
  conexion.query("SELECT * FROM categorias", (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// 2. Obtener incidencias con filtros dinámicos y búsqueda
app.get("/incidencias", (req, res) => {
  const { buscar, categoria_id, estado } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen,
           c.nombre AS categoria, u.nombre AS usuario
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    LEFT JOIN usuarios u ON i.usuario_id = u.id
    WHERE 1=1
  `;
  const parametros = [];

  if (buscar) {
    sql += " AND i.descripcion LIKE ?";
    parametros.push(`%${buscar}%`);
  }
  if (categoria_id) {
    sql += " AND i.categoria_id = ?";
    parametros.push(categoria_id);
  }
  if (estado) {
    sql += " AND i.estado = ?";
    parametros.push(estado);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// 2.1 Exportar incidencias por rango de fechas (reporte PDF)
app.get("/incidencias/exportar", (req, res) => {
  const { fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha,
           c.nombre AS categoria, u.nombre AS usuario
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    LEFT JOIN usuarios u ON i.usuario_id = u.id
    WHERE 1=1
  `;
  const parametros = [];

  if (fecha_inicio && fecha_fin) {
    sql += " AND DATE(i.fecha) BETWEEN ? AND ?";
    parametros.push(fecha_inicio, fecha_fin);
  } else if (fecha_inicio) {
    sql += " AND DATE(i.fecha) >= ?";
    parametros.push(fecha_inicio);
  } else if (fecha_fin) {
    sql += " AND DATE(i.fecha) <= ?";
    parametros.push(fecha_fin);
  }

  sql += " ORDER BY i.fecha DESC";

  conexion.query(sql, parametros, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// 3. Obtener únicamente incidencias RESUELTAS
app.get("/incidencias/resueltas", (req, res) => {
  const sql = `
    SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen,
           c.nombre AS categoria, u.nombre AS usuario
    FROM incidencias i
    JOIN categorias c ON i.categoria_id = c.id
    LEFT JOIN usuarios u ON i.usuario_id = u.id
    WHERE i.estado = 'Resuelto'
    ORDER BY i.fecha DESC
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// 4. Registrar Incidencia con Imagen (requiere sesión)
app.post("/incidencias", verificarToken, upload.single("imagen"), (req, res) => {
  const { categoria_id, descripcion } = req.body;
  const imagen = req.file ? req.file.filename : null;
  const usuario_id = req.usuario.id;
  const sql =
    "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";
  conexion.query(sql, [usuario_id, categoria_id, descripcion, imagen], (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json({
      mensaje: "Incidencia registrada correctamente",
      id: resultado.insertId
    });
  });
});

// 5. Cambiar estado de una incidencia (solo Admin)
app.put("/incidencias/:id/estado", verificarToken, soloAdmin, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;
  const sql = "UPDATE incidencias SET estado = ? WHERE id = ?";
  conexion.query(sql, [estado, id], (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json({ mensaje: "Estado actualizado correctamente" });
  });
});

// 6. Eliminar una incidencia por su ID (solo Admin)
app.delete("/incidencias/:id", verificarToken, soloAdmin, (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM incidencias WHERE id = ?";
  conexion.query(sql, [id], (error, resultado) => {
    if (error) return res.status(500).json(error);
    if (resultado.affectedRows === 0) {
      return res.status(404).json({ mensaje: "Incidencia no encontrada" });
    }
    res.json({ mensaje: "Incidencia eliminada correctamente" });
  });
});

// ---------------- ESTADÍSTICAS ----------------

// 7. Estadísticas agrupadas por categoría
app.get("/estadisticas/categorias", (req, res) => {
  const sql = `
    SELECT c.nombre AS categoria, COUNT(i.id) AS total
    FROM categorias c
    LEFT JOIN incidencias i ON c.id = i.categoria_id
    GROUP BY c.id, c.nombre
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// 8. Estadísticas agrupadas por estado
app.get("/estadisticas/estados", (req, res) => {
  const sql = `
    SELECT estado, COUNT(id) AS total
    FROM incidencias
    GROUP BY estado
  `;
  conexion.query(sql, (error, resultado) => {
    if (error) return res.status(500).json(error);
    res.json(resultado);
  });
});

// ---------------- INICIALIZACIÓN: TABLA USUARIOS Y ADMIN ----------------
const inicializarBaseDeDatos = async () => {
  const db = conexion.promise();

  // Tabla de usuarios
  await db.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL,
      email VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      rol VARCHAR(20) NOT NULL DEFAULT 'Usuario',
      fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Columna fecha_creacion en usuarios (si la tabla ya existía sin ella)
  const [colFecha] = await db.query("SHOW COLUMNS FROM usuarios LIKE 'fecha_creacion'");
  if (colFecha.length === 0) {
    await db.query("ALTER TABLE usuarios ADD COLUMN fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
  }

  // Columna usuario_id en incidencias (si no existe)
  const [columnas] = await db.query("SHOW COLUMNS FROM incidencias LIKE 'usuario_id'");
  if (columnas.length === 0) {
    await db.query("ALTER TABLE incidencias ADD COLUMN usuario_id INT NULL");
  }

  // Administrador inicial desde variables de entorno (no se guarda en el código)
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPass) {
    const [existente] = await db.query("SELECT id FROM usuarios WHERE email = ?", [adminEmail]);
    if (existente.length === 0) {
      const hash = await bcrypt.hash(adminPass, 10);
      await db.query(
        "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, 'Admin')",
        [process.env.ADMIN_NOMBRE || "Administrador", adminEmail, hash]
      );
      console.log("Administrador creado: " + adminEmail);
    }
  }
};

inicializarBaseDeDatos()
  .then(() => {
    app.listen(PORT, () => {
      console.log("Servidor iniciado en el puerto " + PORT + " con autenticación JWT");
    });
  })
  .catch((err) => {
    console.error("Error al inicializar la base de datos:", err.message);
  });