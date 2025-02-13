import express, { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import nodemailer from "nodemailer";
import crypto from "crypto";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import dotenv from "dotenv";
import session from "express-session";

dotenv.config(); // Wczytanie zmiennych środowiskowych

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "supersecret";

app.use(express.json());
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// 📌 **Konfiguracja nodemailer (SMTP, np. Mailtrap)**
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ✅ **Middleware do weryfikacji JWT**
const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.header("Authorization");
  if (!authHeader) {
    res.status(401).json({ error: "Brak tokena!" });
    return;
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      res.status(403).json({ error: "Niepoprawny token!" });
      return;
    }

    (req as any).user = decoded;
    next();
  });
};

// ✅ **Rejestracja użytkownika**
app.post("/register", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ error: "Ten e-mail jest już zajęty!" });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        verificationToken,
      },
    });

    const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Potwierdź swój adres e-mail",
      text: `Kliknij w poniższy link, aby aktywować konto: ${verificationLink}`,
      html: `<a href="${verificationLink}">${verificationLink}</a>`,
    });

    res.json({ message: "Rejestracja udana! Sprawdź e-mail, aby aktywować konto." });

  } catch (error) {
    console.error("Błąd rejestracji:", error);
    res.status(500).json({ error: "Wystąpił błąd serwera." });
  }
});
// ** Weryfikacja rejestracji mailem
app.get("/verify-email", async (req: Request, res: Response): Promise<void> => {
  try {
    const { token } = req.query;

    if (!token || typeof token !== "string") {
      res.status(400).json({ error: "Brak tokena w żądaniu." });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { verificationToken: token },
    });

    if (!user) {
      res.status(400).json({ error: "Niepoprawny token." });
      return;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, verificationToken: null },
    });

    res.json({ message: "Konto zostało zweryfikowane!" });
  } catch (error) {
    console.error("Błąd weryfikacji e-maila:", error);
    res.status(500).json({ error: "Błąd serwera." });
  }
});


// ✅ **Logowanie użytkownika**
app.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    res.status(400).json({ error: "Niepoprawne dane logowania!" });
    return;
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    res.status(400).json({ error: "Niepoprawne dane logowania!" });
    return;
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ message: "Zalogowano!", token });
});
//** Sprawdzanie czy uzytkownik zweryfikował mailem
app.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      res.status(400).json({ error: "Nie znaleziono użytkownika." });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ error: "Niepoprawne hasło." });
      return;
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ message: "Zalogowano pomyślnie!", token });
  } catch (error) {
    console.error("Błąd logowania:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});


// ** Obsługa profilu
app.get("/profile", authenticateToken, async (req: Request, res: Response): Promise<void> => {
  try {
    const userId = (req as any).user?.userId;

    if (!userId) {
      res.status(401).json({ error: "Nieautoryzowany dostęp!" });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true },
    });

    if (!user) {
      res.status(404).json({ error: "Użytkownik nie znaleziony" });
      return;
    }

    res.json({ user });
  } catch (error) {
    console.error("Błąd pobierania profilu:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// ✅ **Edycja profilu użytkownika**
app.put(
  "/update-profile",
  authenticateToken,
  [
    body("email").optional().isEmail().withMessage("Nieprawidłowy email"),
    body("password").optional().isLength({ min: 6 }).withMessage("Hasło musi mieć min. 6 znaków"),
  ],
  async (req: Request, res: Response) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
      }

      const userId = (req as any).user.userId;
      const { email, password } = req.body;
      const updateData: any = {};

      if (email) {
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser && existingUser.id !== userId) {
          res.status(400).json({ error: "Podany email jest już zajęty!" });
          return;
        }
        updateData.email = email;
      }

      if (password) {
        updateData.password = await bcrypt.hash(password, 10);
      }

      if (Object.keys(updateData).length === 0) {
        res.status(400).json({ error: "Nie podano danych do zmiany!" });
        return;
      }

      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: updateData,
      });

      res.json({ message: "Profil zaktualizowany!", user: { id: updatedUser.id, email: updatedUser.email } });
    } catch (error) {
      console.error("Błąd serwera:", error);
      res.status(500).json({ error: "Błąd serwera" });
    }
  }
);


// ✅ **Usuwanie konta użytkownika**
app.delete("/delete-account", authenticateToken, async (req: Request, res: Response) => {
  const userId = (req as any).user.userId;

  try {
    await prisma.user.delete({ where: { id: userId } });
    res.json({ message: "Konto zostało usunięte!" });
  } catch (error) {
    res.status(500).json({ error: "Wystąpił błąd podczas usuwania konta!" });
  }
});

// ✅ **Obsługa OAuth - Google i Facebook**
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await prisma.user.findUnique({ where: { googleId: profile.id } });

      if (!user) {
        const randomPassword = crypto.randomBytes(16).toString("hex");

        user = await prisma.user.create({
          data: {
            googleId: profile.id,
            email: profile.emails?.[0]?.value || `google_user_${profile.id}@example.com`,
            isVerified: true,
            password: randomPassword,
          },
        });
      }

      return done(null, user);
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID!,
      clientSecret: process.env.FACEBOOK_APP_SECRET!,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL!,
      profileFields: ["id", "emails"],
    },
    async (accessToken, refreshToken, profile, done) => {
      let user = await prisma.user.findUnique({ where: { facebookId: profile.id } });

      if (!user) {
        const randomPassword = crypto.randomBytes(16).toString("hex");

        user = await prisma.user.create({
          data: {
            facebookId: profile.id,
            email: profile.emails?.[0]?.value || `facebook_user_${profile.id}@example.com`,
            isVerified: true,
            password: randomPassword,
          },
        });
      }

      return done(null, user);
    }
  )
);

// ✅ **Trasy OAuth**
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email"] }));
app.get("/", (req: Request, res: Response) => {
  res.send("🚀 API działa! Dostępne endpointy: /register, /login, /profile, /auth/google, /auth/facebook");
});

// ✅ **Uruchomienie serwera**
app.listen(PORT, () => {
  console.log(`Serwer uruchomiony na http://localhost:${PORT}`);
});
