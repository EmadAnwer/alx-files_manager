import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import dbClient from '../utils/db';
import redisClient from '../utils/redis';

class AuthController {
  static async getConnect(req, res) {
    const authorization = req.header('Authorization').split(' ')[1];
    console.log(authorization);
    const credentials = Buffer.from(authorization, 'base64').toString('ascii');
    const [email, password] = credentials.split(':');
    const collection = dbClient.client.db().collection('users');
    const hashPassword = crypto
      .createHash('sha1')
      .update(password)
      .digest('hex');
    const findUser = await collection
      .find({
        email,
        password: hashPassword,
      })
      .toArray();
    if (!findUser) {
      return res.status(401).send({ error: 'Unauthorized' });
    }
    const token = crypto.randomUUID();

    await collection.updateOne(
      { email },
      {
        $set: {
          token,
        },
      }
    );
    redisClient.set(token, findUser[0]._id, 86400);

    return res.status(200).send({ token });
  }

  static async getDisconnect(req, res) {
    const token = req.header('X-Token');
    const userId = await redisClient.get(token);
    if (!userId) {
      return res.status(401).send({ error: 'Unauthorized' });
    }
    redisClient.del(token);
    return res.status(204).send();
  }

  static async getMe(req, res) {
    const token = req.header('X-Token');
    const userId = await redisClient.get(token);
    if (!userId) {
      return res.status(401).send({ error: 'Unauthorized' });
    }
    const collection = dbClient.client.db().collection('users');
    const findUser = await collection.findOne({ _id: ObjectId(userId) });
    if (!findUser) {
      return res.status(401).send({ error: 'Unauthorized' });
    }
    return res.status(200).send({ id: findUser._id, email: findUser.email });
  }
}

export default AuthController;
