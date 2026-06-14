require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const validator = require("validator");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const pool = require("./db");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const API_URL = "https://api-ultranetx.onrender.com";

if (!JWT_SECRET) {
    console.error("JWT_SECRET não configurado no .env");
    process.exit(1);
}

if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("EMAIL_USER ou EMAIL_PASS não configurado no .env");
    process.exit(1);
}

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const codigosEmail = {};

const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(helmet());

app.use(cors({
    origin: [
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://api-ultranetx.onrender.com"
    ],
    credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadDir));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { erro: "Muitas tentativas. Tente novamente depois." }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { erro: "Muitas tentativas. Aguarde alguns minutos e tente novamente." }
});

app.use(limiter);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        const nomeSeguro = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`;
        cb(null, nomeSeguro);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024
    },
    fileFilter: (req, file, cb) => {
        const tiposPermitidos = ["image/jpeg", "image/png", "image/webp"];

        if (!tiposPermitidos.includes(file.mimetype)) {
            return cb(new Error("Formato inválido. Use JPG, PNG ou WEBP."));
        }

        cb(null, true);
    }
});

function senhaForte(senha) {
    return (
        typeof senha === "string" &&
        senha.length >= 8 &&
        /[A-Z]/.test(senha) &&
        /[a-z]/.test(senha) &&
        /[0-9]/.test(senha) &&
        /[^A-Za-z0-9]/.test(senha)
    );
}

function idadeValida(dataNascimento) {
    const nascimento = new Date(dataNascimento);
    const hoje = new Date();

    if (isNaN(nascimento.getTime())) return false;

    let idade = hoje.getFullYear() - nascimento.getFullYear();
    const mes = hoje.getMonth() - nascimento.getMonth();

    if (mes < 0 || (mes === 0 && hoje.getDate() < nascimento.getDate())) {
        idade--;
    }

    return idade >= 16;
}

function gerarToken(usuario) {
    return jwt.sign(
        {
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email
        },
        JWT_SECRET,
        { expiresIn: "7d" }
    );
}

function autenticarToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ erro: "Token não enviado ou inválido." });
    }

    const token = authHeader.split(" ")[1];

    try {
        const dados = jwt.verify(token, JWT_SECRET);
        req.usuario = dados;
        next();
    } catch {
        return res.status(401).json({ erro: "Token expirado ou inválido." });
    }
}

app.get("/", (req, res) => {
    res.json({
        mensagem: "API UltraNetX funcionando.",
        api: API_URL
    });
});

app.get("/api/auth/check-email", async (req, res) => {
    try {
        const email = String(req.query.email || "").trim().toLowerCase();

        console.log("CHECK EMAIL RECEBIDO:", email);

        if (!email || !validator.isEmail(email)) {
            return res.status(400).json({ erro: "E-mail inválido." });
        }

        const result = await pool.query(
            "SELECT id FROM usuarios WHERE email = $1",
            [email]
        );

        return res.json({
            disponivel: result.rows.length === 0
        });

    } catch (error) {
        console.error("ERRO CHECK EMAIL REAL:", error);

        return res.status(500).json({
            erro: error.message,
            codigo: error.code,
            detalhe: error.detail || null
        });
    }
});

app.post("/api/auth/enviar-codigo", authLimiter, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();

        if (!email || !validator.isEmail(email)) {
            return res.status(400).json({ erro: "E-mail inválido." });
        }

        const existe = await pool.query(
            "SELECT id FROM usuarios WHERE email = $1",
            [email]
        );

        if (existe.rows.length > 0) {
            return res.status(409).json({ erro: "Este e-mail já está cadastrado." });
        }

        const codigo = crypto.randomInt(100000, 999999).toString();

        codigosEmail[email] = {
            codigo,
            verificado: false,
            expira: Date.now() + 10 * 60 * 1000
        };

        await transporter.sendMail({
            from: `"UltraNetX" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Código de verificação - UltraNetX",
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2>UltraNetX</h2>
                    <p>Seu código de verificação é:</p>
                    <h1 style="font-size: 36px; letter-spacing: 4px;">${codigo}</h1>
                    <p>Esse código expira em 10 minutos.</p>
                    <p>Se você não pediu esse código, ignore este e-mail.</p>
                </div>
            `
        });

        return res.json({ mensagem: "Código enviado com sucesso." });

    } catch (error) {
        console.log("ERRO AO ENVIAR CÓDIGO:", error);
        return res.status(500).json({ erro: "Erro interno ao enviar código." });
    }
});

app.post("/api/auth/verificar-codigo", authLimiter, (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const codigo = String(req.body.codigo || "").trim();

    if (!email || !validator.isEmail(email)) {
        return res.status(400).json({ erro: "E-mail inválido." });
    }

    if (!/^\d{6}$/.test(codigo)) {
        return res.status(400).json({ erro: "Código inválido." });
    }

    const dados = codigosEmail[email];

    if (!dados) {
        return res.status(400).json({ erro: "Nenhum código foi enviado para este e-mail." });
    }

    if (Date.now() > dados.expira) {
        delete codigosEmail[email];
        return res.status(400).json({ erro: "Código expirado. Envie outro código." });
    }

    if (dados.codigo !== codigo) {
        return res.status(400).json({ erro: "Código incorreto." });
    }

    codigosEmail[email].verificado = true;

    return res.json({ mensagem: "E-mail verificado com sucesso." });
});

app.post("/api/auth/cadastro", authLimiter, upload.single("foto"), async (req, res) => {
    try {
        const nome = String(req.body.nome || "").trim().toLowerCase();
        const email = String(req.body.email || "").trim().toLowerCase();
        const senha = String(req.body.senha || "");
        const nascimento = String(req.body.nascimento || "").trim();

        if (!nome || !email || !senha || !nascimento) {
            return res.status(400).json({ erro: "Preencha todos os campos." });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ erro: "E-mail inválido." });
        }

        const codigoInfo = codigosEmail[email];

        if (!codigoInfo || !codigoInfo.verificado) {
            return res.status(400).json({
                erro: "Você precisa verificar o código enviado ao e-mail antes de cadastrar."
            });
        }

        if (!/^[a-zA-Z0-9._]{3,20}$/.test(nome)) {
            return res.status(400).json({
                erro: "Nome deve ter 3 a 20 caracteres e usar apenas letras, números, ponto ou underline."
            });
        }

        if (!senhaForte(senha)) {
            return res.status(400).json({
                erro: "Senha fraca. Use mínimo 8 caracteres, maiúscula, minúscula, número e especial."
            });
        }

        if (!idadeValida(nascimento)) {
            return res.status(400).json({ erro: "Você precisa ter no mínimo 16 anos." });
        }

        const existe = await pool.query(
            "SELECT id FROM usuarios WHERE email = $1 OR nome = $2",
            [email, nome]
        );

        if (existe.rows.length > 0) {
            return res.status(409).json({ erro: "E-mail ou nome de usuário já cadastrado." });
        }

        const senhaHash = await bcrypt.hash(senha, 12);

        const fotoUrl = req.file
            ? `${API_URL}/uploads/${req.file.filename}`
            : null;

        const novoUsuario = await pool.query(
            `INSERT INTO usuarios 
            (nome, email, senha_hash, nascimento, foto_url) 
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, nome, email, nascimento, foto_url, criado_em`,
            [nome, email, senhaHash, nascimento, fotoUrl]
        );

        delete codigosEmail[email];

        const usuario = novoUsuario.rows[0];
        const token = gerarToken(usuario);

        return res.status(201).json({
            mensagem: "Cadastro realizado com sucesso.",
            token,
            usuario
        });

    } catch (error) {
        console.log("ERRO CADASTRO:", error);

        if (req.file) {
            fs.unlink(req.file.path, () => {});
        }

        return res.status(500).json({ erro: "Erro interno ao cadastrar usuário." });
    }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const senha = String(req.body.senha || "");

        if (!email || !senha) {
            return res.status(400).json({ erro: "Informe e-mail e senha." });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ erro: "E-mail inválido." });
        }

        const result = await pool.query(
            "SELECT * FROM usuarios WHERE email = $1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ erro: "E-mail ou senha incorretos." });
        }

        const usuario = result.rows[0];

        const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaCorreta) {
            return res.status(401).json({ erro: "E-mail ou senha incorretos." });
        }

        const token = gerarToken(usuario);

        return res.json({
            mensagem: "Login realizado com sucesso.",
            token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                nascimento: usuario.nascimento,
                foto_url: usuario.foto_url,
                criado_em: usuario.criado_em
            }
        });

    } catch (error) {
        console.log("ERRO LOGIN:", error);
        return res.status(500).json({ erro: "Erro interno ao fazer login." });
    }
});

app.get("/api/me", autenticarToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, nome, email, nascimento, foto_url, criado_em FROM usuarios WHERE id = $1",
            [req.usuario.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ erro: "Usuário não encontrado." });
        }

        return res.json({ usuario: result.rows[0] });

    } catch (error) {
        console.log("ERRO ME:", error);
        return res.status(500).json({ erro: "Erro ao buscar perfil." });
    }
});

app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({ erro: "A imagem deve ter no máximo 2MB." });
        }

        return res.status(400).json({ erro: "Erro no upload da imagem." });
    }

    if (error.message && error.message.includes("Formato inválido")) {
        return res.status(400).json({ erro: error.message });
    }

    console.log("ERRO GLOBAL:", error);
    return res.status(500).json({ erro: "Erro interno no servidor." });
});

app.use((req, res) => {
    res.status(404).json({ erro: "Rota não encontrada." });
});

app.listen(PORT, async () => {
    console.log(`API rodando em http://localhost:${PORT}`);
    console.log(`API pública: ${API_URL}`);

    try {
        await pool.query("SELECT NOW()");
        console.log("PostgreSQL conectado com sucesso.");

        await transporter.verify();
        console.log("Gmail conectado com sucesso.");
    } catch (error) {
        console.error("Erro ao iniciar serviços:");
        console.error(error);
    }
});