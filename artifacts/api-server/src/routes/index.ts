import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scansRouter from "./scans";
import authRouter from "./auth";
import adminRouter from "./admin";
import toolsRouter from "./tools";
import localAuthRouter from "./local-auth";
import testAIRouter from "./test-ai";

const router: IRouter = Router();

router.use(healthRouter);
router.use(localAuthRouter);
router.use(authRouter);
router.use(adminRouter);
router.use(scansRouter);
router.use(toolsRouter);
router.use(testAIRouter);

export default router;
