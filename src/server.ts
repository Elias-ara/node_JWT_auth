import bcrypt from "bcryptjs";
import Fastify from "fastify";

const app = Fastify({ logger: true });

interface User {
  id: number;
  username: string;
  email: string;
  password: string;
}

const users: User[] = [];

app.get("/", async () => {
  return { users };
});

app.post("/users/register", async (request, reply) => {
  const { username, email, password } = request.body as {
    username: string;
    email: string;
    password: string;
  };
  const user = users.find((u) => u.email === email);
  if (user) {
    return reply.status(409).send({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser: User = {
    id: users.length + 1,
    username,
    email,
    password: hashedPassword,
  };
  users.push(newUser);

  return reply.status(201).send({ message: "User registered successfully" });
});

const start = async () => {
  try {
    await app.listen({ port: 3333 });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
