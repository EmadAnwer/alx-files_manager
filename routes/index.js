import { Router } from 'express';
import AppController from '../controllers/AppController';

const router = new Router();

router.get('/status', AppController.getStatus);
router.get('/stats', AppController.getStats);

export default router;
