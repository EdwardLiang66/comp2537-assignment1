require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();
const PORT = process.env.PORT || 3000;
const DEMO_PASSWORD = "Password123!";

const {
  MONGODB_HOST,
  MONGODB_USER,
  MONGODB_PASSWORD,
  MONGODB_DATABASE,
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
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl,
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

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  res.locals.currentPath = req.path;
  next();
});

function createUserSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) {
        reject(err);
        return;
      }

      req.session.user = {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        isAdmin: Boolean(user.isAdmin),
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

function requireLogin(req, res, next) {
  if (!req.session.user) {
    res.redirect("/login");
    return;
  }

  next();
}

const signupSchema = Joi.object({
  name: Joi.string().trim().max(50).required().messages({
    "string.empty": "Please provide a name.",
    "any.required": "Please provide a name.",
    "string.max": "Name must be 50 characters or less.",
  }),
  email: Joi.string().trim().lowercase().email().max(100).required().messages({
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
  email: Joi.string().trim().lowercase().email().max(100).required().messages({
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
  res.render("home", {
    title: "Home",
  });
});

app.get("/signup", (req, res) => {
  res.render("signup", {
    title: "Sign up",
    error: null,
    values: {},
  });
});

app.post("/signup", async (req, res) => {
  const validationResult = signupSchema.validate(req.body, {
    abortEarly: true,
    stripUnknown: true,
  });

  if (validationResult.error) {
    res.status(400).render("signup", {
      title: "Sign up",
      error: validationResult.error.details[0].message,
      values: req.body,
    });
    return;
  }

  const { name, email, password } = validationResult.value;

  try {
    const existingUser = await usersCollection.findOne({ email });

    if (existingUser) {
      res.status(400).render("signup", {
        title: "Sign up",
        error: "A user with this email already exists.",
        values: { name, email },
      });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const insertResult = await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      isAdmin: false,
      createdAt: new Date(),
    });

    await createUserSession(req, {
      _id: insertResult.insertedId,
      name,
      email,
      isAdmin: false,
    });

    res.redirect("/members");
  } catch (err) {
    console.error(err);
    res.status(500).render("message", {
      title: "Server error",
      heading: "Server error",
      message: "Could not create user.",
      linkHref: "/signup",
      linkText: "Try again",
    });
  }
});

app.get("/login", (req, res) => {
  res.render("login", {
    title: "Log in",
    error: null,
    values: {},
  });
});

app.post("/login", async (req, res) => {
  const validationResult = loginSchema.validate(req.body, {
    abortEarly: true,
    stripUnknown: true,
  });

  if (validationResult.error) {
    res.status(400).render("login", {
      title: "Log in",
      error: validationResult.error.details[0].message,
      values: req.body,
    });
    return;
  }

  const { email, password } = validationResult.value;

  try {
    const user = await usersCollection.findOne({ email });

    if (!user) {
      res.status(401).render("login", {
        title: "Log in",
        error: "Invalid email/password combination.",
        values: { email },
      });
      return;
    }

    const passwordMatches = await bcrypt.compare(password, user.password);

    if (!passwordMatches) {
      res.status(401).render("login", {
        title: "Log in",
        error: "Invalid password.",
        values: { email },
      });
      return;
    }

    await createUserSession(req, user);
    res.redirect("/members");
  } catch (err) {
    console.error(err);
    res.status(500).render("message", {
      title: "Server error",
      heading: "Server error",
      message: "Could not log in.",
      linkHref: "/login",
      linkText: "Try again",
    });
  }
});

app.get("/members", requireLogin, (req, res) => {
  res.render("members", {
    title: "Members",
    images: [
      { src: "/img1.jpg", alt: "Member gallery image 1" },
      { src: "/img2.jpg", alt: "Member gallery image 2" },
      { src: "/img3.jpg", alt: "Member gallery image 3" },
    ],
  });
});

app.get("/admin", requireLogin, async (req, res) => {
  if (!req.session.user.isAdmin) {
    res.status(403).render("message", {
      title: "Admin access denied",
      heading: "Admin access denied",
      message: "You are logged in, but your account is not an admin.",
      linkHref: "/members",
      linkText: "Back to members",
    });
    return;
  }

  const users = await usersCollection
    .find({}, { projection: { password: 0 } })
    .sort({ isAdmin: -1, email: 1 })
    .toArray();

  res.render("admin", {
    title: "Admin",
    users,
    message: req.query.message || null,
  });
});

app.post("/admin/users/:id/role", requireLogin, async (req, res) => {
  if (!req.session.user.isAdmin) {
    res.status(403).render("message", {
      title: "Admin access denied",
      heading: "Admin access denied",
      message: "You are logged in, but your account is not an admin.",
      linkHref: "/members",
      linkText: "Back to members",
    });
    return;
  }

  const { id } = req.params;
  const { action } = req.body;

  if (!ObjectId.isValid(id) || !["promote", "demote"].includes(action)) {
    res.status(400).render("message", {
      title: "Invalid admin action",
      heading: "Invalid admin action",
      message: "That admin change could not be completed.",
      linkHref: "/admin",
      linkText: "Back to admin",
    });
    return;
  }

  const isAdmin = action === "promote";
  await usersCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { isAdmin } },
  );

  if (req.session.user.id === id) {
    req.session.user.isAdmin = isAdmin;
  }

  const message = isAdmin ? "User promoted to admin." : "User demoted from admin.";
  res.redirect(`/admin?message=${encodeURIComponent(message)}`);
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      res.status(500).render("message", {
        title: "Logout error",
        heading: "Logout error",
        message: "Could not log out.",
        linkHref: "/",
        linkText: "Home",
      });
      return;
    }

    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).render("message", {
    title: "404",
    heading: "Page not found - 404",
    message: "The page you requested does not exist.",
    linkHref: "/",
    linkText: "Back to home",
  });
});

async function seedAssignmentUsers() {
  const hashedPassword = await bcrypt.hash(DEMO_PASSWORD, 12);
  const demoUsers = [
    {
      name: "Admin User",
      email: "admin@email.com",
      isAdmin: true,
    },
    {
      name: "Regular User",
      email: "user@email.com",
      isAdmin: false,
    },
  ];

  for (const user of demoUsers) {
    await usersCollection.updateOne(
      { email: user.email },
      {
        $set: {
          name: user.name,
          password: hashedPassword,
          isAdmin: user.isAdmin,
        },
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      { upsert: true },
    );
  }
}

async function startServer() {
  const client = new MongoClient(mongoUrl);
  await client.connect();

  const db = client.db(MONGODB_DATABASE);
  usersCollection = db.collection("users");

  await usersCollection.createIndex({ email: 1 }, { unique: true });
  await seedAssignmentUsers();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:");
  console.error(err);
  process.exit(1);
});
