import { Router } from "express";
import { requireAuth } from "../middleware/requireAuth";
import { prisma } from "../prisma";

const router = Router();

router.get("/me", requireAuth, async (req, res) => {
  const auth = (req as any).auth as { sub: string };

  const user = await prisma.user.findUnique({
    where: { id: auth.sub },
    select: { id: true, email: true, createdAt: true, updatedAt: true },
  });

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  return res.status(200).json({ user });
});

export default router;