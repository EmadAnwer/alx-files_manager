import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import dbClient from '../utils/db';
import redisClient from '../utils/redis';

class UsersController {
  static async postNew(req, res) {
    const { email, password } = req.body;
    if (!email) return res.status(400).send({ error: 'Missing email' });
    if (!password) return res.status(400).send({ error: 'Missing password' });
    const collection = dbClient.client.db().collection('users');
    const findUser = await collection.find({ email }).toArray();

    if (findUser.length > 0) {
      return res.status(400).send({ error: 'Already exist' });
    }
    // hash password
    const hashPassword = crypto
      .createHash('sha1')
      .update(password)
      .digest('hex');

    const result = await collection.insertOne({
      email,
      password: hashPassword,
    });

    return res.status(201).send({ id: result.insertedId, email });
  }

  static async getMe(req, res) {
    const token = req.header('X-Token');
    const userId = await redisClient.get(`auth_${token}`);
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

export default UsersController;
