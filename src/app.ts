import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import crypto from "crypto";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import dotenv from "dotenv";
import session from "express-session";
import nodemailer from "nodemailer";

dotenv.config();
console.log("GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID);
console.log("GOOGLE_CLIENT_SECRET:", process.env.GOOGLE_CLIENT_SECRET);

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "supersecret";

app.use(express.json());
app.use(cors());
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user: any, done) => {
  // Zapisujemy tylko identyfikator użytkownika do sesji
  done(null, user.id);
});

passport.deserializeUser(async (id: number, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});
//** Czyszczenie bazy danych


// Middleware do weryfikacji JWT
const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
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

// Konfiguracja nodemailer (używając Gmaila)
// Pamiętaj, aby EMAIL_USER i EMAIL_PASS były ustawione na poprawne dane,
// tzn. adres Gmail oraz wygenerowane hasło aplikacji, jeśli masz włączone 2FA.
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  logger: true,
  debug: true,
});
//** Callback dla google-a
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req: Request, res: Response) => {
    const user: any = req.user;
    const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
    res.redirect(`http://localhost:5173/profile?token=${token}`);
  }
);

//** Callback dla facebooka
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req: Request, res: Response, next) => {
    console.log("Facebook callback reached");
    if (!req.user) {
      console.error("Brak użytkownika po autoryzacji przez Facebooka");
      return next(new Error("Nie znaleziono użytkownika po autoryzacji przez Facebooka."));
    }
    req.logIn(req.user as any, (err) => {
      if (err) {
        console.error("Błąd przy logIn:", err);
        return next(err);
      }
      const user: any = req.user;
      const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
      console.log("User zalogowany, przekierowywanie do profilu z tokenem:", token);
      return res.redirect(`http://localhost:5173/profile?token=${token}`);
    });
  }
);




// ✅ Rejestracja użytkownika z weryfikacją e-mail oraz sprawdzeniem potwierdzenia hasła
app.post("/register", async (req: Request, res: Response): Promise<void> => {
  try {
    // Pobieramy email, password oraz confirmPassword z ciała żądania
    const { email, password, confirmPassword } = req.body;

    // Sprawdzenie obecności obu haseł
    if (!password || !confirmPassword) {
      res.status(400).json({ error: "Oba pola hasła muszą być wypełnione." });
      return;
    }

    // Sprawdzamy, czy hasła są identyczne (po trimowaniu zbędnych spacji)
    if (password.trim() !== confirmPassword.trim()) {
      res.status(400).json({ error: "Hasła muszą być identyczne." });
      return;
    }

    // Sprawdzamy, czy użytkownik o podanym e-mailu już istnieje
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ error: "Ten e-mail jest już zajęty!" });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    // Tworzymy użytkownika jako niezweryfikowanego
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        isVerified: false,
        verificationToken: verificationToken,
      },
    });

    // Przygotowujemy link weryfikacyjny
    const verificationLink = `http://localhost:${PORT}/verify-email?token=${verificationToken}`;

    // Wysyłamy e-mail weryfikacyjny
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Potwierdź swój adres e-mail",
      text: `Kliknij w link, aby zweryfikować swoje konto: ${verificationLink}`,
      html: `<p>Kliknij <a href="${verificationLink}">tutaj</a>, aby zweryfikować swoje konto.</p>`,
    });

    res.json({
      message: "Rejestracja udana! Sprawdź e-mail, aby aktywować konto.",
    });
  } catch (error) {
    console.error("Błąd rejestracji:", error);
    res.status(500).json({ error: "Wystąpił błąd serwera." });
  }
});

// ✅ Endpoint weryfikacji e-mail
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

    res.json({ message: "Konto zostało pomyślnie zweryfikowane!" });
  } catch (error) {
    console.error("Błąd weryfikacji e-maila:", error);
    res.status(500).json({ error: "Błąd serwera." });
  }
});

// ✅ Logowanie użytkownika – tylko dla zweryfikowanych kont
app.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      res.status(400).json({ error: "Nie znaleziono użytkownika." });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({ error: "Konto nie zostało zweryfikowane. Sprawdź swój e-mail." });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      res.status(401).json({ error: "Niepoprawne hasło." });
      return;
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    res.json({ message: "Zalogowano pomyślnie!", token });
  } catch (error) {
    console.error("Błąd logowania:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// ✅ Obsługa profilu (wymaga uwierzytelnienia)
app.get(
  "/profile",
  authenticateToken,
  async (req: Request, res: Response): Promise<void> => {
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
  }
);

// ✅ Edycja profilu użytkownika (wymaga uwierzytelnienia)
app.put(
  "/update-profile",
  authenticateToken,
  [
    body("email").optional().isEmail().withMessage("Nieprawidłowy email"),
    body("password")
      .optional()
      .isLength({ min: 6 })
      .withMessage("Hasło musi mieć min. 6 znaków"),
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

      res.json({
        message: "Profil zaktualizowany!",
        user: { id: updatedUser.id, email: updatedUser.email },
      });
    } catch (error) {
      console.error("Błąd serwera:", error);
      res.status(500).json({ error: "Błąd serwera" });
    }
  }
);

// ✅ Usuwanie konta użytkownika (wymaga uwierzytelnienia)
app.delete("/delete-account", authenticateToken, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    await prisma.user.delete({ where: { id: userId } });
    res.json({ message: "Konto zostało usunięte!" });
  } catch (error) {
    res.status(500).json({ error: "Wystąpił błąd podczas usuwania konta!" });
  }
});

// ✅ Obsługa OAuth - Google i Facebook
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Szukamy użytkownika po googleId
        let user = await prisma.user.findUnique({ where: { googleId: profile.id } });
        
        // Jeśli nie znaleziono, szukamy użytkownika po emailu (jeśli email jest dostępny)
        if (!user) {
          const email = profile.emails?.[0]?.value;
          if (email) {
            user = await prisma.user.findUnique({ where: { email } });
          }
        }

        // Jeśli użytkownik istnieje, ale nie ma przypisanego googleId, aktualizujemy rekord
        if (user && !user.googleId) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { googleId: profile.id, isVerified: true },
          });
        }

        // Jeśli użytkownik nadal nie istnieje, tworzymy nowego użytkownika
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
      } catch (error) {
        return done(error, false);
      }
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
      try {
        console.log("Facebook profile:", profile);
        let user = await prisma.user.findUnique({ where: { facebookId: profile.id } });
        console.log("Found by facebookId:", user);
        if (!user) {
          const email = profile.emails?.[0]?.value;
          console.log("Email from Facebook:", email);
          if (email) {
            user = await prisma.user.findUnique({ where: { email } });
            console.log("Found by email:", user);
          }
        }
        if (user && !user.facebookId) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { facebookId: profile.id, isVerified: true },
          });
          console.log("Updated user with facebookId:", user);
        }
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
          console.log("Created new user:", user);
        }
        return done(null, user);
      } catch (error) {
        console.error("Błąd w strategii Facebook:", error);
        return done(error, false);
      }
    }
  )
);



// Trasy OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email"] }));

app.get("/", (req: Request, res: Response) => {
  res.send("🚀 API działa! Dostępne endpointy: /register, /login, /profile, /auth/google, /auth/facebook");
});

// Uruchomienie serwera
app.listen(PORT, () => {
  console.log(`Serwer uruchomiony na http://localhost:${PORT}`);
});
