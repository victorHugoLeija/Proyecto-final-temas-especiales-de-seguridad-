require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(cors());

app.use(express.json({ limit: '10kb' }));

function sanitizeNoSQL(value) {
    if (Array.isArray(value)) {
        return value.map(sanitizeNoSQL);
    }

    if (value && typeof value === 'object') {
        const cleanObject = {};

        for (const key in value) {
            if (key.startsWith('$') || key.includes('.')) {
                continue;
            }

            cleanObject[key] = sanitizeNoSQL(value[key]);
        }

        return cleanObject;
    }

    return value;
}


app.use((req, res, next) => {
    req.body = sanitizeNoSQL(req.body);
    next();
});

app.use(express.static(__dirname));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: 'Demasiados intentos. Intenta de nuevo más tarde.' }
});

mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log('MongoDB conectado');
        await seedAdminUser();
    })
    .catch((error) => console.error('Error al conectar MongoDB:', error));

function createSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt) {
    return crypto
        .createHash('sha256')
        .update(salt + password)
        .digest('hex');
}

function isValidEmail(email) {
    return /^\S+@\S+\.\S+$/.test(email);
}

function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 8;
}

function isValidText(value, maxLength = 500) {
    return typeof value === 'string' && value.trim().length > 0 && value.length <= maxLength;
}

function isValidPhone(phone) {
    return typeof phone === 'string' && /^\+?[0-9\s\-()]{7,20}$/.test(phone.trim());
}

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    salt: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
}, { strict: true });

const contactSchema = new mongoose.Schema({
    userEmail: String,
    name: String,
    email: String,
    phone: String,
    eventDate: String,
    eventTime: String,
    plan: String,
    message: String,
    status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
    completedAt: Date,
    createdAt: { type: Date, default: Date.now }
}, { strict: true });

const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    rating: { type: Number, min: 1, max: 5, default: 5 },
    message: { type: String, required: true },
    eventType: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    adminNote: String,
    approvedAt: Date,
    createdAt: { type: Date, default: Date.now }
}, { strict: true });

const User = mongoose.model('User', userSchema);
const Contact = mongoose.model('Contact', contactSchema);
const Review = mongoose.model('Review', reviewSchema);

async function seedAdminUser() {
    const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const adminPassword = process.env.ADMIN_PASSWORD || '';

    if (!adminEmail || !adminPassword) {
        console.log('Admin no configurado en .env');
        return;
    }

    const existingAdmin = await User.findOne({ email: adminEmail });

    if (existingAdmin) {
        const passwordHash = hashPassword(adminPassword, existingAdmin.salt);

        if (passwordHash !== existingAdmin.passwordHash) {
            const newSalt = createSalt();
            existingAdmin.salt = newSalt;
            existingAdmin.passwordHash = hashPassword(adminPassword, newSalt);
        }

        if (existingAdmin.role !== 'admin') {
            existingAdmin.role = 'admin';
        }

        await existingAdmin.save();
        return;
    }

    const salt = createSalt();
    const passwordHash = hashPassword(adminPassword, salt);

    await User.create({
        email: adminEmail,
        passwordHash,
        salt,
        role: 'admin'
    });

    console.log(`Admin creado: ${adminEmail}`);
}

function createToken(email, role = 'user') {
    return jwt.sign({ email, role }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.status(401).json({ message: 'Sesión no válida. Inicia sesión nuevamente.' });
    }
}

function verifyAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Acceso solo para administrador.' });
    }

    next();
}

app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ message: 'Datos inválidos.' });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({ message: 'Correo no válido.' });
        }

        if (!isValidPassword(password)) {
            return res.status(400).json({ message: 'La contraseña debe tener mínimo 8 caracteres.' });
        }

        const existingUser = await User.findOne({ email: normalizedEmail });

        if (existingUser) {
            return res.status(400).json({ message: 'Ya existe una cuenta con ese email.' });
        }

        const salt = createSalt();
        const passwordHash = hashPassword(password, salt);

        await User.create({
            email: normalizedEmail,
            passwordHash,
            salt
        });

        const token = createToken(normalizedEmail, 'user');

        res.json({
            message: 'Cuenta creada correctamente.',
            email: normalizedEmail,
            role: 'user',
            token
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al crear la cuenta.' });
    }
});

app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ message: 'Correo o contraseña incorrectos.' });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({ message: 'Correo o contraseña incorrectos.' });
        }

        const user = await User.findOne({ email: normalizedEmail });

        if (!user) {
            return res.status(400).json({ message: 'Correo o contraseña incorrectos.' });
        }

        const passwordHash = hashPassword(password, user.salt);

        if (passwordHash !== user.passwordHash) {
            return res.status(400).json({ message: 'Correo o contraseña incorrectos.' });
        }

        const role = user.role || 'user';
        const token = createToken(user.email, role);

        res.json({
            message: 'Inicio de sesión correcto.',
            email: user.email,
            role,
            token
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al iniciar sesión.' });
    }
});

app.post('/api/contact', verifyToken, async (req, res) => {
    try {
        const { name, email, phone, eventDate, eventTime, plan, message } = req.body;

        if (
            !isValidText(name, 100) ||
            !isValidText(email, 100) ||
            !isValidPhone(phone) ||
            !isValidText(eventDate, 30) ||
            !isValidText(eventTime, 30) ||
            !isValidText(message, 1000)
        ) {
            return res.status(400).json({ message: 'Datos inválidos o incompletos.' });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (!isValidEmail(normalizedEmail)) {
            return res.status(400).json({ message: 'Correo no válido.' });
        }

        await Contact.create({
            userEmail: req.user.email,
            name: name.trim(),
            email: normalizedEmail,
            phone: phone.trim(),
            eventDate: eventDate.trim(),
            eventTime: eventTime.trim(),
            plan: typeof plan === 'string' ? plan.trim() : '',
            message: message.trim(),
            status: 'pending'
        });

        res.json({ message: 'Solicitud guardada correctamente.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al guardar la solicitud.' });
    }
});

app.get('/api/reviews', async (req, res) => {
    try {
        const reviews = await Review.find({ status: 'approved' })
            .sort({ createdAt: -1 })
            .limit(30)
            .lean();

        res.json({ reviews });
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener reseñas.' });
    }
});

app.post('/api/reviews', async (req, res) => {
    try {
        const { name, rating, message, eventType } = req.body;
        const numericRating = Number(rating);

        if (
            !isValidText(name, 80) ||
            !Number.isFinite(numericRating) ||
            numericRating < 1 ||
            numericRating > 5 ||
            !isValidText(message, 700)
        ) {
            return res.status(400).json({ message: 'Datos de reseña inválidos o incompletos.' });
        }

        await Review.create({
            name: name.trim(),
            rating: numericRating,
            message: message.trim(),
            eventType: typeof eventType === 'string' ? eventType.trim() : '',
            status: 'pending'
        });

        res.json({ message: 'Reseña enviada. Será visible cuando el administrador la apruebe.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al guardar la reseña.' });
    }
});

app.get('/api/admin/contacts', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const contacts = await Contact.find({})
            .sort({ createdAt: -1 })
            .limit(100)
            .lean();

        res.json({ contacts });
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener solicitudes.' });
    }
});

app.get('/api/admin/reviews', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const reviews = await Review.find({})
            .sort({ createdAt: -1 })
            .limit(100)
            .lean();

        res.json({ reviews });
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener reseñas.' });
    }
});

app.patch('/api/admin/reviews/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { name, rating, message, eventType, status, adminNote } = req.body;
        const update = {};

        if (name !== undefined) {
            if (!isValidText(name, 80)) return res.status(400).json({ message: 'Nombre no válido.' });
            update.name = name.trim();
        }

        if (rating !== undefined) {
            const numericRating = Number(rating);
            if (!Number.isFinite(numericRating) || numericRating < 1 || numericRating > 5) {
                return res.status(400).json({ message: 'Calificación no válida.' });
            }
            update.rating = numericRating;
        }

        if (message !== undefined) {
            if (!isValidText(message, 700)) return res.status(400).json({ message: 'Reseña no válida.' });
            update.message = message.trim();
        }

        if (eventType !== undefined) {
            update.eventType = typeof eventType === 'string' ? eventType.trim() : '';
        }

        if (adminNote !== undefined) {
            update.adminNote = typeof adminNote === 'string' ? adminNote.trim() : '';
        }

        if (status !== undefined) {
            if (!['pending', 'approved', 'rejected'].includes(status)) {
                return res.status(400).json({ message: 'Estado de reseña no válido.' });
            }
            update.status = status;
            update.approvedAt = status === 'approved' ? new Date() : null;
        }

        const review = await Review.findByIdAndUpdate(req.params.id, update, { new: true }).lean();

        if (!review) {
            return res.status(404).json({ message: 'Reseña no encontrada.' });
        }

        res.json({ review });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar reseña.' });
    }
});

app.delete('/api/admin/reviews/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const deletedReview = await Review.findByIdAndDelete(req.params.id).lean();

        if (!deletedReview) {
            return res.status(404).json({ message: 'Reseña no encontrada.' });
        }

        res.json({ message: 'Reseña eliminada correctamente.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar reseña.' });
    }
});

app.patch('/api/admin/contacts/:id/status', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        if (!['pending', 'completed'].includes(status)) {
            return res.status(400).json({ message: 'Estado no válido.' });
        }

        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            {
                status,
                completedAt: status === 'completed' ? new Date() : null
            },
            { new: true }
        ).lean();

        if (!contact) {
            return res.status(404).json({ message: 'Solicitud no encontrada.' });
        }

        res.json({ contact });
    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar solicitud.' });
    }
});

app.delete('/api/admin/contacts/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const deletedContact = await Contact.findByIdAndDelete(req.params.id).lean();

        if (!deletedContact) {
            return res.status(404).json({ message: 'Solicitud no encontrada.' });
        }

        res.json({ message: 'Solicitud eliminada correctamente.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al eliminar solicitud.' });
    }
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(process.env.PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${process.env.PORT}`);
});
