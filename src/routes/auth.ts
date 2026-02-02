import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcrypt";
import { prisma } from "../prisma";
import jwt from "jsonwebtoken";
import { config } from "../config";

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

router.post("/register", async (req, res) => {
  try {
    const { email, password } = registerSchema.parse(req.body);

    const existing = await prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (existing) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
      },
    });

    return res.status(201).json({ user });
  } catch (err: any) {
    // Zod validation error
    if (err?.name === "ZodError") {
      return res.status(400).json({
        message: "Invalid request body",
        errors: err.errors,
      });
    }

    console.error(err);
    return res.status(500).json({ message: "Internal server error" });
  }
});


const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);

    if (!ok) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email },
      config.jwtSecret,
      { expiresIn: "7d" }
    );

    return res.status(200).json({ token });
  } catch (err: any) {
    if (err?.name === "ZodError") {
      return res.status(400).json({
        message: "Invalid request body",
        errors: err.errors,
      });
    }

    console.error(err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

export default router;