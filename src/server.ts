import bcrypt from "bcryptjs";
import Fastify from "fastify";
import jwt from "jsonwebtoken";

const app = Fastify({ logger: true });

const JWT_SECRET = "SuperPassword123";

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
  const { username, email, password } = request.body as {
    username: string;
    email: string;
    password: string;
  };

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
