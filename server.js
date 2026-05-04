require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();
const PORT = process.env.PORT || 3000;

const {
  MONGODB_HOST,
  MONGODB_USER,
  MONGODB_PASSWORD,
  MONGODB_DATABASE,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET,
} = process.env;

function requireEnv(name) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

[
  "MONGODB_HOST",
  "MONGODB_USER",
  "MONGODB_PASSWORD",
  "MONGODB_DATABASE",
  "MONGODB_SESSION_SECRET",
  "NODE_SESSION_SECRET",
].forEach(requireEnv);

const encodedUser = encodeURIComponent(MONGODB_USER);
const encodedPassword = encodeURIComponent(MONGODB_PASSWORD);

const mongoUrl = `mongodb+srv://${encodedUser}:${encodedPassword}@${MONGODB_HOST}/${MONGODB_DATABASE}?retryWrites=true&w=majority`;

let usersCollection;

app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

app.use(
  session({
    secret: NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: mongoUrl,
      dbName: MONGODB_DATABASE,
      collectionName: "sessions",
      ttl: 60 * 60,
    }),
    cookie: {
      maxAge: 1000 * 60 * 60,
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    },
  }),
);

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function page(title, body) {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>${escapeHtml(title)}</title>
        <link rel="stylesheet" href="/style.css">
      </head>
      <body>
        <main>
          ${body}
        </main>
      </body>
    </html>
  `;
}

function messagePage(title, message, linkHref, linkText) {
  return page(
    title,
    `
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
      <p><a href="${linkHref}">${escapeHtml(linkText)}</a></p>
    `,
  );
}

function createUserSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) {
        reject(err);
        return;
      }

      req.session.user = {
        name: user.name,
        email: user.email,
      };

      req.session.save((saveErr) => {
        if (saveErr) {
          reject(saveErr);
          return;
        }

        resolve();
      });
    });
  });
}

const signupSchema = Joi.object({
  name: Joi.string().trim().max(50).required().messages({
    "string.empty": "Please provide a name.",
    "any.required": "Please provide a name.",
    "string.max": "Name must be 50 characters or less.",
  }),
  email: Joi.string().trim().email().max(100).required().messages({
    "string.empty": "Please provide an email address.",
    "any.required": "Please provide an email address.",
    "string.email": "Please provide a valid email address.",
    "string.max": "Email must be 100 characters or less.",
  }),
  password: Joi.string().max(100).required().messages({
    "string.empty": "Please provide a password.",
    "any.required": "Please provide a password.",
    "string.max": "Password must be 100 characters or less.",
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().trim().email().max(100).required().messages({
    "string.empty": "Please provide an email address.",
    "any.required": "Please provide an email address.",
    "string.email": "Please provide a valid email address.",
    "string.max": "Email must be 100 characters or less.",
  }),
  password: Joi.string().max(100).required().messages({
    "string.empty": "Please provide a password.",
    "any.required": "Please provide a password.",
    "string.max": "Password must be 100 characters or less.",
  }),
});

app.get("/", (req, res) => {
  if (req.session.user) {
    const name = escapeHtml(req.session.user.name);

    res.send(
      page(
        "Home",
        `
          <h1>Hello, ${name}.</h1>
          <p><a class="button" href="/members">Go to Members Area</a></p>
          <p><a class="button" href="/logout">Logout</a></p>
        `,
      ),
    );
    return;
  }

  res.send(
    page(
      "Home",
      `
        <h1>COMP 2537 Assignment 1</h1>
        <p><a class="button" href="/signup">Sign up</a></p>
        <p><a class="button" href="/login">Log in</a></p>
      `,
    ),
  );
});

app.get("/signup", (req, res) => {
  res.send(
    page(
      "Sign up",
      `
        <h1>Create user</h1>

        <form method="POST" action="/signup">
          <input name="name" type="text" placeholder="name">
          <input name="email" type="text" placeholder="email">
          <input name="password" type="password" placeholder="password">
          <button type="submit">Submit</button>
        </form>

        <p><a href="/">Back to home</a></p>
      `,
    ),
  );
});

app.post("/signup", async (req, res) => {
  const validationResult = signupSchema.validate(req.body, {
    abortEarly: true,
    stripUnknown: true,
  });

  if (validationResult.error) {
    res
      .status(400)
      .send(
        messagePage(
          "Sign up error",
          validationResult.error.details[0].message,
          "/signup",
          "Try again",
        ),
      );
    return;
  }

  const { name, email, password } = validationResult.value;

  try {
    const existingUser = await usersCollection.findOne({ email });

    if (existingUser) {
      res
        .status(400)
        .send(
          messagePage(
            "Sign up error",
            "A user with this email already exists.",
            "/signup",
            "Try again",
          ),
        );
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      createdAt: new Date(),
    });

    await createUserSession(req, { name, email });

    res.redirect("/members");
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .send(
        messagePage(
          "Server error",
          "Could not create user.",
          "/signup",
          "Try again",
        ),
      );
  }
});

app.get("/login", (req, res) => {
  res.send(
    page(
      "Log in",
      `
        <h1>Log in</h1>

        <form method="POST" action="/login">
          <input name="email" type="text" placeholder="email">
          <input name="password" type="password" placeholder="password">
          <button type="submit">Submit</button>
        </form>

        <p><a href="/">Back to home</a></p>
      `,
    ),
  );
});

app.post("/login", async (req, res) => {
  const validationResult = loginSchema.validate(req.body, {
    abortEarly: true,
    stripUnknown: true,
  });

  if (validationResult.error) {
    res
      .status(400)
      .send(
        messagePage(
          "Login error",
          validationResult.error.details[0].message,
          "/login",
          "Try again",
        ),
      );
    return;
  }

  const { email, password } = validationResult.value;

  try {
    const user = await usersCollection.findOne({ email });

    if (!user) {
      res
        .status(401)
        .send(
          messagePage(
            "Login error",
            "Invalid email/password combination.",
            "/login",
            "Try again",
          ),
        );
      return;
    }

    const passwordMatches = await bcrypt.compare(password, user.password);

    if (!passwordMatches) {
      res
        .status(401)
        .send(
          messagePage(
            "Login error",
            "Invalid password.",
            "/login",
            "Try again",
          ),
        );
      return;
    }

    await createUserSession(req, {
      name: user.name,
      email: user.email,
    });

    res.redirect("/members");
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .send(
        messagePage("Server error", "Could not log in.", "/login", "Try again"),
      );
  }
});

app.get("/members", (req, res) => {
  if (!req.session.user) {
    res.redirect("/");
    return;
  }

  const images = ["/img1.jpg", "/img2.jpg", "/img3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  const name = escapeHtml(req.session.user.name);

  res.send(
    page(
      "Members",
      `
        <h1>Hello, ${name}.</h1>

        <img class="member-image" src="${randomImage}" alt="Random member image">

        <p><a class="button" href="/logout">Sign out</a></p>
      `,
    ),
  );
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res
        .status(500)
        .send(messagePage("Logout error", "Could not log out.", "/", "Home"));
      return;
    }

    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).send(
    page(
      "404",
      `
        <h1>Page not found - 404</h1>
        <p>The page you requested does not exist.</p>
        <p><a href="/">Back to home</a></p>
      `,
    ),
  );
});

async function startServer() {
  const client = new MongoClient(mongoUrl);
  await client.connect();

  const db = client.db(MONGODB_DATABASE);
  usersCollection = db.collection("users");

  await usersCollection.createIndex({ email: 1 }, { unique: true });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:");
  console.error(err);
  process.exit(1);
});
