import bcrypt from "bcryptjs";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import jwt from "jsonwebtoken";

const app = Fastify({ logger: true });

const JWT_SECRET = process.env.JWT_SECRET || "SuperPassword123";

//define a estrutura do token JWT decodificado
interface JwtUser {
  id: number;
  email: string;
  iat: number;
  exp: number;
}

//utilização da tecnica de declaration merging para adicionar o campo user ao FastifyRequest
declare module "fastify" {
  export interface FastifyRequest {
    user?: {
      id: number;
      email: string;
      iat: number;
      exp: number;
    };
  }
}

//middleware de autenticacao
async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return reply.status(401).send({ message: "Token not provided" });
    }

    const token = authHeader.replace("Bearer ", "");
    const decodedJwt = jwt.verify(token, JWT_SECRET) as JwtUser;
    request.user = decodedJwt;
  } catch (error) {
    return reply.status(401).send({ message: "Invalid or expired token" });
  }
}
interface User {
  id: number;
  username: string;
  email: string;
  password: string;
}

//Criacao do banco de dados em memoria
const users: User[] = [];

// Rota para testar se o servidor esta funcionando
app.get("/", async () => {
  return { users };
});

// Rota para registrar um novo usuario
app.post("/users/register", async (request, reply) => {
  const { username, email, password } = request.body as {
    username: string;
    email: string;
    password: string;
  };

  // Valida campos obrigatórios
  if (!username || !email || !password) {
    return reply.status(400).send({ message: "Username, email and password are required" });
  }

  // Valida formato do email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return reply.status(400).send({ message: "Invalid email format" });
  }

  // Valida tamanho mínimo da senha
  if (password.length < 6) {
    return reply.status(400).send({ message: "Password must be at least 6 characters" });
  }

  // Verifica se o usuario ja existe
  const user = users.find((u) => u.email === email);
  if (user) {
    return reply.status(409).send({ message: "User already exists" });
  }

  //encripta a senha do usuario
  const hashedPassword = await bcrypt.hash(password, 10);

  // Cria um novo usuario
  const newUser: User = {
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
  };
  users.push(newUser);

  return reply.status(201).send({ message: "User registered successfully" });
});

// Rota para login do usuario
app.post("/users/login", async (request, reply) => {
  const { email, password } = request.body as {
    email: string;
    password: string;
  };

  // Valida campos obrigatórios
  if (!email || !password) {
    return reply.status(400).send({ message: "Email and password are required" });
  }

  // Verifica se o usuario existe
  const user = users.find((u) => u.email === email);
  if (!user) {
    return reply.status(401).send({ message: "invalid credentials" });
  }

  // Verifica se a senha esta correta
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return reply.status(401).send({ message: "invalid credentials" });
  }

  // Gera um token JWT
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "1h",
  });
  return { token };
});

// Rota protegida para obter informacoes do usuario autenticado
app.get("/me", { onRequest: [authenticate] }, async (request, reply) => {
  return request.user;
});

// Inicia o servidor
const start = async () => {
  try {
    await app.listen({ port: 3333 });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
