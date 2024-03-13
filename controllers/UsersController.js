import crypto from 'crypto';
import dbClient from '../utils/db';

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
}

export default UsersController;
