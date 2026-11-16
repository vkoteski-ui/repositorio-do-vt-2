// npm init -y
// npm i express mysql2 bcrypt jsonwebtoken dotenv cors

require("dotenv").config()
const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cors = require("cors")

const db = require("./db")
const { criar_tabelas } = require("./migration")

const app = express()
const port = process.env.PORT || 3000

app.use(express.json())
app.use(cors())

// ===================== MIDDLEWARE JWT =====================

function autenticar(req, res, next) {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({
            erro: "Token não enviado. Use: Authorization: Bearer <token>"
        })
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
        if (err) {
            return res.status(403).json({ erro: "Token inválido ou expirado" })
        }
        req.usuario = usuario
        next()
    })
}

// ===================== ROTAS PÚBLICAS =====================

// POST /cliente → Cadastro
app.post("/cliente", async (req, res) => {
    try {
        const cliente = req.body
        const senhaCript = bcrypt.hashSync(cliente.senha, 10)

        const [resultado] = await db.pool.query(
            `INSERT INTO cliente (nome, cpf, celular, email, senha)
             VALUES (?, ?, ?, ?, ?)`,
            [cliente.nome, cliente.cpf, cliente.celular, cliente.email, senhaCript]
        )

        res.status(201).json({
            mensagem: "Cliente cadastrado com sucesso! ID = " + resultado.insertId
        })
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// POST /login → Autenticação
app.post("/login", async (req, res) => {
    try {
        const { email, senha } = req.body

        const [rows] = await db.pool.query(
            "SELECT id, nome, email, senha FROM cliente WHERE email = ?",
            [email]
        )

        const dados_bd = rows[0]

        if (!dados_bd) {
            return res.status(401).json({ mensagem: "Email não cadastrado!" })
        }

        const senha_valida = await bcrypt.compare(senha, dados_bd.senha)

        if (!senha_valida) {
            return res.status(401).json({ mensagem: "Credenciais inválidas!" })
        }

        const payload = {
            id: dados_bd.id,
            email: dados_bd.email
        }

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "2h" })

        return res.status(200).json({
            nome: dados_bd.nome,
            token: token
        })
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// ===================== ROTAS DE CLIENTE =====================

// GET /cliente/perfil → Rota protegida (DEVE vir antes de /cliente/:id)
app.get("/cliente/perfil", autenticar, async (req, res) => {
    try {
        const id = req.usuario.id
        const [rows] = await db.pool.query(
            "SELECT id, nome, cpf, celular, email FROM cliente WHERE id = ?",
            [id]
        )

        const perfil = rows[0]

        if (!perfil) {
            return res.status(404).json({ erro: "Cliente não encontrado" })
        }

        res.status(200).json(perfil)
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// GET /cliente → Listar todos
app.get("/cliente", async (req, res) => {
    try {
        const [rows] = await db.pool.query(
            "SELECT id, nome, cpf, celular, email FROM cliente"
        )
        res.status(200).json(rows)
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// GET /cliente/:id → Buscar por ID
app.get("/cliente/:id", async (req, res) => {
    try {
        const { id } = req.params
        const [rows] = await db.pool.query(
            "SELECT id, nome, cpf, celular, email FROM cliente WHERE id = ?",
            [id]
        )

        if (rows.length === 0) {
            return res.status(404).json({ mensagem: "Cliente não encontrado" })
        }

        res.status(200).json(rows[0])
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// PUT /cliente/:id → Atualizar
app.put("/cliente/:id", async (req, res) => {
    try {
        const { id } = req.params
        const { nome, cpf, celular, email } = req.body

        const [resultado] = await db.pool.query(
            `UPDATE cliente
             SET nome = ?, cpf = ?, celular = ?, email = ?
             WHERE id = ?`,
            [nome, cpf, celular, email, id]
        )

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensagem: "Cliente não encontrado" })
        }

        res.status(200).json({ mensagem: "Cliente alterado com sucesso" })
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})

// DELETE /cliente/:id → Excluir
app.delete("/cliente/:id", async (req, res) => {
    try {
        const { id } = req.params
        const [resultado] = await db.pool.query(
            "DELETE FROM cliente WHERE id = ?",
            [id]
        )

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensagem: "Cliente não encontrado" })
        }

        res.status(200).json({ mensagem: "Cliente excluído com sucesso" })
    } catch (error) {
        res.status(500).json({ erro: error.message })
    }
})



// ===================== INICIAR SERVIDOR =====================

async function iniciar() {
    try {
        console.log("🔄 Executando migration...")
        await criar_tabelas()
        console.log("✅ Migration concluída!")

        app.listen(port, () => {
            console.log(`🚀 API rodando na porta ${port}`)
        })
    } catch (error) {
        console.error("❌ Erro ao iniciar a API:", error.message)
        process.exit(1)
    }
}

iniciar()